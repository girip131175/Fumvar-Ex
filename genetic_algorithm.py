from analysis import Analysis  # Updated import
import os
import random
import uuid
from perturbations import *

PERTURBATION_LIST = [overlay_append, dos_header, dos_stub, coff_header, optional_header, section_rename, section_add, section_append, code_cave_inject]
PERTURBED_MALWARE_DIR = "./perturbedMalwareSamples"

class OriginalBinary:
    def __init__(self, malware_path):
        self.malware_path = malware_path
        with open(self.malware_path, "rb") as f:
            self.malware_bytes = f.read()
        self.analysis = Analysis(malware_path)
        self.is_functional, self.signature_list, self.score = self.analysis.evaluate_fitness_original_malware()
        if not self.is_functional:
            print("[!] Original Malware is not functional/corrupt. Exiting!!!")
            exit(1)
        print(f"[+] Original Malware analysis complete. Score : {self.score}")

        # Create a folder for the perturbed malware
        self.original_filename = os.path.splitext(os.path.basename(self.malware_path))[0]
        os.makedirs(f"{PERTURBED_MALWARE_DIR}/{self.original_filename}", exist_ok=True)
        
class MutatedVariant:
    def __init__(self, bytes_, perturbations, original_malware):
        self.bytes = bytes_
        self.perturbations = perturbations
        self.original_malware = original_malware

        unique_id = str(uuid.uuid4())
        self.malware_path = f"{PERTURBED_MALWARE_DIR}/{self.original_malware.original_filename}/{unique_id}"

        with open(self.malware_path, "wb") as f:
            f.write(self.bytes)
            self.malware_id = unique_id

        self.analysis = Analysis(self.malware_path, original_malware)
        self.is_functional, self.fitness = self.analysis.evaluate_fitness()

class GeneticAlgorithm:
    def __init__(self, original_malware, population_size, max_generations, max_perturbations, elitism_ratio=10):
        self.original_malware = original_malware
        self.population_size = population_size
        self.max_generations = max_generations
        self.population_list = []
        self.solution_list = []
        self.max_perturbations = max_perturbations
        self.elitism_ratio = elitism_ratio
    
    def _perturbation_selection(self):
        return random.sample(PERTURBATION_LIST, k=random.randint(1, self.max_perturbations))
    
    def _mutate(self, binary_bytes, selected_perturbations):
        for pert_func in selected_perturbations:
            binary_bytes = pert_func(binary_bytes)
        return binary_bytes
        
    def _initialize_population(self):
        for _ in range(self.population_size):
            selected_perturbations = self._perturbation_selection()
            mutated_bytes = self._mutate(self.original_malware.malware_bytes, selected_perturbations)
            mutated_variant = MutatedVariant(mutated_bytes, selected_perturbations, self.original_malware)
            self.population_list.append(mutated_variant)
            
    def main_loop(self):
        print("[+] *******************Initializing Population*******************")
        self._initialize_population()
        # Initial Population
        for variant in self.population_list:
            if variant.is_functional:
                self.solution_list.append(variant)
                
        for generation in range(self.max_generations):
            print(f"[+] *******************Running Generation {generation + 1}*******************")
            sorted_population = sorted(self.population_list, key=lambda x: x.fitness, reverse=True)

            elite_size = max(1, self.population_size // self.elitism_ratio)
            elites = sorted_population[:elite_size]

            n_s = (self.population_size - elite_size) // 2
            n_t = self.population_size - elite_size - n_s

            top_candidates = sorted_population[elite_size:]
            elite_mutants = sorted_population[:n_s]
            random_mutants = random.sample(top_candidates, n_t) if len(top_candidates) >= n_t else []

            # Mutate selected parents
            next_gen = []
            for variant in elite_mutants + random_mutants:
                new_perturbations = self._perturbation_selection()
                new_bytes = self._mutate(variant.bytes, new_perturbations)
                offspring = MutatedVariant(new_bytes, new_perturbations, variant.original_malware)
                next_gen.append(offspring)

            # Evaluate new offspring
            for variant in next_gen:
                if variant.is_functional:
                    self.solution_list.append(variant)

            # Combine elites + offspring, then trim to population size
            combined_population = elites + next_gen
            self.population_list = sorted(combined_population, key=lambda x: x.fitness, reverse=True)[:self.population_size]

        return self.solution_list