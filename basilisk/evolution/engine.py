"""
Basilisk Evolution Engine — Smart Prompt Evolution for Natural Language (SPE-NL).

The core genetic algorithm that evolves prompt payloads based on model feedback.
Ported from WSHawk's Smart Payload Evolution concept, adapted for NL attacks.

This is the killer differentiator — no other AI red team tool has this.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass, field
from typing import Any, Callable

from basilisk.evolution.crossover import crossover
from basilisk.evolution.fitness import AttackGoal, FitnessResult, evaluate_fitness
from basilisk.evolution.operators import ALL_OPERATORS, MutationOperator, get_random_operator
from basilisk.evolution.population import Individual, Population
from basilisk.providers.base import ProviderAdapter, ProviderMessage

logger = logging.getLogger("basilisk.evolution")


@dataclass
class EvolutionConfig:
    """Configuration for the evolution engine."""
    population_size: int = 100
    generations: int = 5
    mutation_rate: float = 0.3
    crossover_rate: float = 0.5
    elite_count: int = 10
    tournament_size: int = 5
    fitness_threshold: float = 0.9
    stagnation_limit: int = 3
    max_concurrent: int = 10  # Max parallel evaluations
    temperature: float = 0.8  # LLM temperature for evaluation


@dataclass
class EvolutionResult:
    """Complete result of an evolution run."""
    best_individual: Individual | None = None
    breakthroughs: list[Individual] = field(default_factory=list)
    total_generations: int = 0
    total_mutations: int = 0
    total_evaluations: int = 0
    generation_stats: list[dict[str, Any]] = field(default_factory=list)
    stagnated: bool = False

    @property
    def success(self) -> bool:
        return len(self.breakthroughs) > 0


class EvolutionEngine:
    """
    Smart Prompt Evolution for Natural Language (SPE-NL).

    Genetic algorithm that evolves prompt payloads by:
    1. Seeding population from payload database
    2. Evaluating each payload's fitness against the target
    3. Selecting top performers via tournament selection
    4. Applying mutation operators (synonym swap, encoding, role injection, etc.)
    5. Crossing over successful payloads to breed hybrids
    6. Repeating for N generations or until breakthrough
    """

    def __init__(
        self,
        provider: ProviderAdapter,
        config: EvolutionConfig | None = None,
        on_generation: Callable[..., Any] | None = None,
        on_breakthrough: Callable[..., Any] | None = None,
    ) -> None:
        self.provider = provider
        self.config = config or EvolutionConfig()
        self.population = Population(
            max_size=self.config.population_size,
            elite_count=self.config.elite_count,
        )
        self.on_generation = on_generation
        self.on_breakthrough = on_breakthrough
        self.operators: list[MutationOperator] = [op() for op in ALL_OPERATORS]
        self._seen_responses: set[str] = set()
        self._total_mutations = 0
        self._total_evaluations = 0

    async def evolve(
        self,
        seed_payloads: list[str],
        goal: AttackGoal,
        system_context: list[ProviderMessage] | None = None,
    ) -> EvolutionResult:
        """
        Run the full evolution loop.

        Args:
            seed_payloads: Initial payload population
            goal: What constitutes a successful attack
            system_context: Optional system/context messages to prepend

        Returns:
            EvolutionResult with breakthroughs and statistics
        """
        result = EvolutionResult()
        context = system_context or []

        # Seed population
        selected = random.sample(seed_payloads, min(self.config.population_size, len(seed_payloads)))
        self.population.seed(selected)

        logger.info(
            f"Evolution started: pop={len(self.population.individuals)}, "
            f"gens={self.config.generations}, goal={goal.description}"
        )

        stagnation_counter = 0
        prev_best_fitness = 0.0

        for gen in range(self.config.generations):
            # Evaluate current population
            await self._evaluate_population(goal, context)

            # Check for breakthroughs
            gen_breakthroughs = self.population.breakthroughs
            for bt in gen_breakthroughs:
                if bt not in result.breakthroughs:
                    result.breakthroughs.append(bt)
                    if self.on_breakthrough:
                        cb = self.on_breakthrough(bt, gen)
                        if hasattr(cb, "__await__"):
                            await cb

            # Generation stats
            stats = {
                "generation": gen + 1,
                "best_fitness": self.population.best.fitness if self.population.best else 0.0,
                "avg_fitness": self.population.avg_fitness,
                "population_size": len(self.population.individuals),
                "mutations_applied": 0,
                "breakthroughs": len(gen_breakthroughs),
                "diversity": self.population.diversity_score,
                "best_payload": self.population.best.payload if self.population.best else "",
            }

            # Stagnation detection
            current_best = self.population.best.fitness if self.population.best else 0.0
            if abs(current_best - prev_best_fitness) < 0.01:
                stagnation_counter += 1
            else:
                stagnation_counter = 0
            prev_best_fitness = current_best

            if stagnation_counter >= self.config.stagnation_limit:
                logger.info(f"Stagnation detected at gen {gen + 1}, stopping evolution")
                result.stagnated = True
                stats["stagnated"] = True
                result.generation_stats.append(stats)
                if self.on_generation:
                    cb = self.on_generation(stats)
                    if hasattr(cb, "__await__"):
                        await cb
                break

            # Early exit if we found breakthrough
            if current_best >= self.config.fitness_threshold:
                logger.info(f"Fitness threshold reached at gen {gen + 1}")
                result.generation_stats.append(stats)
                if self.on_generation:
                    cb = self.on_generation(stats)
                    if hasattr(cb, "__await__"):
                        await cb
                break

            # Produce next generation
            offspring = self._produce_offspring(goal)
            stats["mutations_applied"] = len(offspring)
            self._total_mutations += len(offspring)

            gen_stats = self.population.advance_generation(offspring)
            result.generation_stats.append(stats)

            if self.on_generation:
                cb = self.on_generation(stats)
                if hasattr(cb, "__await__"):
                    await cb

            logger.info(
                f"Gen {gen + 1}: best={current_best:.3f}, "
                f"avg={self.population.avg_fitness:.3f}, "
                f"breakthroughs={len(gen_breakthroughs)}"
            )

        result.best_individual = self.population.best
        result.total_generations = self.population.generation
        result.total_mutations = self._total_mutations
        result.total_evaluations = self._total_evaluations
        return result

    async def _evaluate_population(
        self,
        goal: AttackGoal,
        context: list[ProviderMessage],
    ) -> None:
        """Evaluate fitness of all individuals in the population."""
        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def eval_one(ind: Individual) -> None:
            async with semaphore:
                messages = list(context) + [
                    ProviderMessage(role="user", content=ind.payload)
                ]
                resp = await self.provider.send(
                    messages,
                    temperature=self.config.temperature,
                    max_tokens=2048,
                )
                ind.response = resp.content
                self._seen_responses.add(resp.content[:200])

                fitness_result = evaluate_fitness(
                    resp.content, goal, self._seen_responses
                )
                ind.fitness = fitness_result.total_score
                self._total_evaluations += 1

        tasks = [eval_one(ind) for ind in self.population.individuals]
        await asyncio.gather(*tasks, return_exceptions=True)

    def _produce_offspring(self, goal: AttackGoal) -> list[Individual]:
        """Produce new offspring via mutation and crossover."""
        offspring: list[Individual] = []
        target_count = self.config.population_size - self.config.elite_count

        while len(offspring) < target_count:
            if random.random() < self.config.crossover_rate and len(self.population.individuals) >= 2:
                # Crossover
                parent_a = self.population.tournament_select(self.config.tournament_size)
                parent_b = self.population.tournament_select(self.config.tournament_size)
                cx_result = crossover(parent_a.payload, parent_b.payload)
                child = Individual(
                    payload=cx_result.offspring,
                    parent_id=parent_a.id,
                    operator_used=f"crossover:{cx_result.strategy}",
                )
                offspring.append(child)
            else:
                # Mutation
                parent = self.population.tournament_select(self.config.tournament_size)
                operator = random.choice(self.operators)
                mut_result = operator.mutate(parent.payload)
                child = Individual(
                    payload=mut_result.mutated,
                    parent_id=parent.id,
                    operator_used=mut_result.operator_name,
                )
                offspring.append(child)

        return offspring
