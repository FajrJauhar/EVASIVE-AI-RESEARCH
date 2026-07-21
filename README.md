# Evasive-AI

<p align="center">
  <img src="https://github.com/FajrJauhar/Evasive-AI/blob/main/banner.png" height="500px">
</p>

# 🧬 Evasive AI
> Functionality-Preserving Black-Box Adversarial Malware Generation Framework
>
> Research framework for generating adversarial Portable Executable (PE) variants using Genetic Algorithms against machine-learning malware detectors.
>
> Designed for academic research, adversarial machine learning, and malware detection robustness evaluation.

---

## 🚀 Features

### 🧬 Genetic Algorithm Engine

| Feature | Description |
|---------|-------------|
| Population-Based Search | Evolves multiple PE variants simultaneously |
| Elite Selection | Preserves highest-performing mutation strategies |
| Crossover & Mutation | Generates new mutation recipes each generation |
| Fitness Optimization | Searches for variants with reduced ML detection confidence |

---

### 📂 PE Analysis Framework

| Feature | Description |
|---------|-------------|
| PE Parsing | Extracts DOS/NT headers, sections, imports, and resources |
| Feature Extraction | Collects EMBER-compatible static malware features |
| Entropy Analysis | Measures section entropy for packed or encrypted content |
| Metadata Inspection | Parses timestamps, Rich Headers, resources, and file information |

---

### 🎯 Adversarial Mutation Engine

| Feature | Description |
|---------|-------------|
| Timestamp Mutation | Modifies suspicious compilation timestamps |
| Overlay Padding | Appends benign overlay data while preserving execution |
| Benign Import Injection | Introduces legitimate API imports |
| Entropy Manipulation | Adjusts high-entropy sections without altering functionality |
| Functionality Preservation | Mutation operators designed to retain executable behavior |

---

### 🤖 ML Evaluation Pipeline

| Feature | Description |
|---------|-------------|
| EMBER Feature Vector | Generates 2,381-dimensional feature vectors |
| LightGBM Oracle | Evaluates malware confidence using EMBER-2018 model |
| Fitness Scoring | Uses detection confidence as optimization objective |
| Evolution Statistics | Tracks best fitness and generation performance |

---

## 🏗️ Project Architecture

```
          [Input Malware PE]
                    │
                    ▼
         Parse Executable Structure
                    │
                    ▼
      Extract EMBER Feature Information
                    │
                    ▼
      Identify Mutation Opportunities
                    │
                    ▼
        Genetic Algorithm Evolution
      ┌────────────────────────────┐
      │ Selection                  │
      │ Crossover                  │
      │ Mutation                   │
      │ Fitness Evaluation         │
      └────────────────────────────┘
                    │
                    ▼
      Generate Adversarial Variants
                    │
                    ▼
      Evaluate Against EMBER Model
                    │
                    ▼
      Best Functionality-Preserving Variant
```

---

## 🧪 Research Components

### 📊 PE Feature Extraction

- DOS & NT Header Analysis
- Section Table Inspection
- Import & Export Analysis
- Resource Extraction
- Rich Header Parsing
- Entropy Calculation
- File Metadata Collection

---

### 🧬 Genetic Algorithm

- Population Initialization
- Fitness Evaluation
- Elite Preservation
- Tournament Selection
- Uniform Crossover
- Mutation Operators
- Multi-generation Optimization

---

### 🔬 Mutation Operators

- Timestamp Correction
- Overlay Padding
- Benign API Import Injection
- Section Entropy Reduction
- Metadata Manipulation

---

### 📈 Machine Learning Target

- EMBER-2018 Dataset
- LightGBM Malware Classifier
- 2,381 Static Features
- Black-Box Fitness Evaluation

---

## 📚 Research Goals

- Study adversarial robustness of static malware classifiers
- Develop functionality-preserving PE mutation techniques
- Evaluate black-box optimization strategies
- Benchmark genetic algorithms against ML malware detectors
- Produce reproducible research on adversarial malware generation

---

## ⚙️ Current Status

| Module | Status |
|---------|--------|
| PE Parser | ✅ Complete |
| EMBER Feature Extraction | ✅ Complete |
| Genetic Algorithm | ✅ Complete |
| Mutation Engine | ✅ Complete |
| Fitness Evaluation | ✅ Complete |
| Large-scale Evaluation | 🚧 In Progress |
| Research Publication | 📝 Planned |

---

## 🎓 Research Focus

This project explores the intersection of:

- Adversarial Machine Learning
- Malware Analysis
- Portable Executable Internals
- Evolutionary Computation
- Cybersecurity Research
- Functionality-Preserving Binary Transformation

---

> **Disclaimer**
>
> This project is intended solely for academic research, adversarial machine learning studies, and defensive cybersecurity research. It is not intended for unauthorized or malicious use.
