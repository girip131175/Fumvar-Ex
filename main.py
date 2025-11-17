import argparse
import os
from genetic_algorithm import OriginalBinary, GeneticAlgorithm
from llm_interface import get_best_malware_sample

def main():
    parser = argparse.ArgumentParser(description="Run Genetic Algorithm on a malware sample.")
    parser.add_argument("-i", "--input", required=True, help="Path to the malware binary file")
    parser.add_argument("-s", "--population-size", required=True, type=int, help="Size of population in each generation")
    parser.add_argument("-g", "--max-generations", required=True, type=int, help="Number of generations to run")
    parser.add_argument("-p", "--max-perturbations", required=True, type=int, help="Maximum perturbations per generation")
    args = parser.parse_args()

    print("[+] Starting MCP server to select best malware sample...")
    best_sample_path = get_best_malware_sample(os.path.abspath(args.input))
    if not os.path.exists(best_sample_path):
        print("[!] Failed to obtain a valid path from LLM Interface. Exiting.")
        return

    print(f"[+] Proceeding with sample: {best_sample_path}")
    ob = OriginalBinary(best_sample_path)
    ga = GeneticAlgorithm(ob, args.population_size, args.max_generations, args.max_perturbations)

    solution_list = ga.main_loop()
    solution_list.sort(key=lambda x: x.fitness, reverse=True)

    print("[+] Final Result")
    for i, member in enumerate(solution_list):
        print(f"[+] Member {i+1}, ID: {member.malware_id}")
        print(f"    [+] Fitness Score: {member.fitness}")
        print(f"    [+] Hybrid Score: {member.analysis.hybrid_score}")
        print(f"    [+] SSDEEP Score: {member.analysis.ssdeep_difference}")
        print(f"    [+] Signature Similarity Score: {member.analysis.signature_score}")

if __name__ == "__main__":
    main()