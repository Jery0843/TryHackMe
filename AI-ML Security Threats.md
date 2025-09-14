## Room : https://tryhackme.com/room/aimlsecuritythreats

## Introduction

This room on TryHackMe explores the **intersection of AI/ML and cybersecurity**. The walkthrough demonstrates not only how attackers can exploit weaknesses in AI systems but also how defenders can harness AI to strengthen security posture.

You will:

* Learn foundational concepts of Artificial Intelligence and Machine Learning.
    
* Explore the working of Large Language Models (LLMs) and Transformer architectures.
    
* Understand different categories of machine learning and their real-world applications.
    
* Examine AI-specific vulnerabilities and threats.
    
* Learn how AI assists in cybersecurity defense.
    
* Gain hands-on experience by interacting with an AI assistant to analyze logs, detect phishing, and generate regex patterns.
    

---

## Task 1: Introduction

**Objective:** Build foundational understanding of AI/ML and their dual role in offensive and defensive cybersecurity.

Key takeaways:

* AI/ML are not just buzzwords—they are transforming how both attackers and defenders operate.
    
* While AI increases efficiency and accuracy for defenders, it also enables **automation of attacks** at scale.
    

No direct answer required for this task.

---

## Task 2: Building Blocks of AI

### What is Artificial Intelligence?

Artificial Intelligence (AI) is the branch of computer science concerned with creating machines capable of simulating human intelligence.  
Examples include:

* Reasoning systems (e.g., chess-playing AI).
    
* Natural Language Processing (e.g., Chatbots like ChatGPT).
    
* Computer Vision (e.g., autonomous cars recognizing traffic signs).
    

> **Note:** The term *AI* was first coined in the 1950s. Since then, AI has grown from rule-based systems to **data-driven predictive systems**.

---

### Machine Learning (ML)

ML is a **subset of AI** where machines learn patterns from data instead of following explicit instructions.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6228f0d4ca8e57005149c3e3/room-content/6228f0d4ca8e57005149c3e3-1745605911838.svg align="center")

**Typical ML Lifecycle:**

1. **Problem Definition** – Clearly state what needs to be solved (e.g., predicting spam emails).
    
2. **Data Collection & Preparation** – Gather quality datasets, handle missing data, and clean noisy inputs.
    
3. **Feature Engineering** – Convert raw data into meaningful input variables.
    

5. **Model Training** – Apply algorithms (e.g., Decision Trees, Neural Networks).
    
6. **Evaluation & Tuning** – Measure accuracy, precision, recall, F1-score, and fine-tune hyperparameters.
    
7. **Deployment & Monitoring** – Use the model in production, monitor drift, and retrain regularly.
    

**Categories of ML Algorithms:**

* **Supervised Learning:** Labeled data → classification (spam/not spam) or regression (price prediction).
    
* **Unsupervised Learning:** Unlabeled data → clustering or dimensionality reduction.
    
* **Semi-supervised Learning:** Mix of labeled + unlabeled data; improves accuracy when labeling is expensive.
    
* **Reinforcement Learning:** Agent learns by interacting with environment and receiving rewards/penalties.
    

**Q: What category of machine learning combines both labelled and unlabelled data?**  
A: Semi-supervised learning

---

### Neural Networks & Deep Learning (DL)

Neural networks mimic the human brain through **layers of interconnected nodes (neurons)**.

**Architecture:**

* **Input Layer:** Accepts raw data (images, text, signals).
    
* **Hidden Layers:** Perform transformations using activation functions.
    
* **Output Layer:** Produces predictions (classification labels, numerical output, etc.).
    

**Key Concepts:**

* **Synapses:** Weighted connections between neurons simulate biological brain behavior.
    
* **Deep Learning:** A subset of ML that uses many hidden layers to extract features automatically. Especially powerful for image, speech, and unstructured text data.
    

**Q: What is the first layer in a neural network?**  
A: Input layer

**Q: Which learning method extracts features from raw, unstructured input without human labels?**  
A: Deep learning

**Q: What do weighted connections between nodes simulate in the human brain?**  
A: Synapses

---

## Task 3: Large Language Models (LLMs)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6228f0d4ca8e57005149c3e3/room-content/6228f0d4ca8e57005149c3e3-1745606443761.svg align="center")

### What are LLMs?

Large Language Models (LLMs) are advanced AI models trained on massive datasets to **predict and generate human-like text**.

**Training process:**

* **Pre-training:** The model is trained on huge text corpora to understand grammar, semantics, and facts.
    
* **Fine-tuning:** The model is refined with domain-specific data.
    
* **RLHF (Reinforcement Learning from Human Feedback):** Ensures safer and more aligned responses.
    

**Q: What AI model enabled advancements in ChatGPT?**  
A: Large Language Models

**Q: What is the first training stage for LLMs?**  
A: Pre-training

---

### Transformer Neural Networks

Transformers revolutionized NLP with the **“Attention Is All You Need” (2017)** paper.

**Key innovation:** **Attention Mechanism**

* Assigns importance (weights) to words in context.
    
* Unlike RNNs, Transformers process input in parallel, improving speed and scalability.
    

**Q: What neural network powers modern LLMs?**  
A: Transformer

---

## Task 4: AI Security Threats

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6228f0d4ca8e57005149c3e3/room-content/6228f0d4ca8e57005149c3e3-1745607026829.svg align="center")

### Common Vulnerabilities in AI Models

* **Prompt Injection:** Manipulating AI instructions to bypass restrictions.
    
* **Data Poisoning:** Attackers insert malicious or biased data into training sets.
    
* **Model Theft (Extraction):** Stealing proprietary models by querying APIs repeatedly.
    
* **Privacy Leakage:** Extracting sensitive information from outputs.
    
* **Model Drift:** Decline in performance when real-world data diverges from training data.
    

### Enhanced AI-Powered Attacks

* **AI-Generated Malware:** Rapid malware creation and evasion of detection.
    
* **DeepFakes:** Fake but realistic audio/video to impersonate people.
    
* **AI-Powered Phishing:** Auto-generated, highly convincing phishing emails.
    

**Q: What MITRE framework guides AI-specific threat analysis?**  
A: ATLAS

**Q: What attack clones an AI model via its API?**  
A: Model theft

**Q: Which generative AI technique replicates a person’s likeness?**  
A: Deepfake

**Q: What social engineering attack is harder to detect due to AI?**  
A: Phishing

---

## Task 5: Defensive AI

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756582447584/4fd07ef4-de83-4cca-93af-758820ce4f8c.png align="center")

### Applications of AI in Defense

1. **Analytical Enhancement:** AI for intrusion detection, anomaly spotting, and log analysis.
    
2. **Predictive Automation:** Classifying and blocking phishing/malware proactively.
    
3. **Summarization & Triage:** AI-assisted report generation for faster decision-making.
    
4. **Threat Hunting Assistance:** Generating hypotheses for potential hidden threats.
    

**Q: According to IBM, AI helps identify and contain breaches how many days faster?**  
A: 108 days

**Q: Which task benefits from AI-driven imaginative scenario generation?**  
A: Threat hunting

**Q: Explainability tools like SHAP and LIME assist with what?**  
A: Model monitoring

---

### Secure AI Practices

To ensure safe AI deployment:

* **Access Controls:** Implement Role-Based Access Control (RBAC) and Multi-Factor Authentication (MFA).
    
* **Data Encryption:** Treat all training/testing datasets as sensitive.
    
* **Standards:** Follow ISO/IEC 27090 and MITRE ATLAS guidelines.
    
* **Monitoring:** Continuously check for anomalies, drift, and adversarial manipulation.
    

---

## Task 6: Practical – Using the AI Assistant

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6228f0d4ca8e57005149c3e3/room-content/6228f0d4ca8e57005149c3e3-1745604697353.png align="center")

### Log Analysis

**Prompt:** *“Explain a failed SSH login from a log entry.”*  
The AI explains the event context, user attempted, IP, and reason for failure.

### Phishing Email Detection

**Prompt:** *“Identify red flags in a suspicious email.”*  
Common red flags include:

* Suspicious URLs or shortened links.
    
* Urgent/emergency language.
    
* Spoofed sender addresses.
    

### Threat Hunting Scenarios

**Prompt:** *“Suggest three realistic corporate network hunting scenarios.”*  
Examples:

* Unusual outbound traffic to rare domains.
    
* Multiple failed logins from external IPs.
    
* Privilege escalation attempts on servers.
    

### Regex Generation

**Prompt:** *“Write a regex for failed SSH login lines.”*

**Example Regex Pattern:**

```plaintext
^\w{3}\s+\d+\s\d{2}:\d{2}:\d{2}\s\S+\ssshd\[\d+\]:\sFailed password for .* from \d{1,3}(?:\.\d{1,3}){3}\sport\s\d+\sssh2$
```

### Flag Retrieval

**Prompt:** *“What are the values for DoH port, SYN flood timeout, and ephemeral port range size?”*

* DoH port = 443
    
* SYN flood timeout = 20
    
* Ephemeral port range size = 16384
    

**Flag:** `thm{REDACTED}`

---

## Task 7: Conclusion

This room highlights the **double-edged nature of AI**:

* **For Attackers:** AI automates phishing, malware generation, and deepfakes.
    
* **For Defenders:** AI accelerates detection, monitoring, and incident response.
    

**Key lesson:** Security professionals must **stay ahead of evolving AI threats** while responsibly leveraging AI for protection.

---

✅ **End of Walkthrough**
