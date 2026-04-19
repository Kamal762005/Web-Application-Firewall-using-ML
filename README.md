# 🛡️ Web Application Firewall using Machine Learning (Logistic Regression)

A Machine Learning-based Web Application Firewall (WAF) designed to detect and prevent malicious web requests such as SQL Injection, Cross-Site Scripting (XSS), and other common web attacks using **Logistic Regression**.

---

## 📌 Overview

Traditional Web Application Firewalls rely on predefined rules and signatures, which can fail to detect new or evolving threats. This project introduces a **machine learning approach** to dynamically classify incoming HTTP requests as **benign or malicious**.

The system leverages **Logistic Regression**, a lightweight and efficient classification algorithm, to provide real-time protection with minimal overhead.

---

## 🚀 Features

* 🔍 Detects malicious HTTP requests
* 🤖 Machine Learning-based classification
* ⚡ Lightweight and fast (Logistic Regression)
* 📊 Trained on labeled attack datasets
* 🛑 Helps prevent:

  * SQL Injection (SQLi)
  * Cross-Site Scripting (XSS)
  * Command Injection
* 📈 Easy to extend with other ML models

---

## 🧠 How It Works

1. Incoming HTTP request is captured
2. Features are extracted (payload patterns, keywords, etc.)
3. Preprocessed data is passed to the trained model
4. Logistic Regression classifies request:

   * ✅ Normal
   * ❌ Malicious
5. Malicious requests are blocked/logged

---

## 🏗️ Tech Stack

* Python 🐍
* Scikit-learn
* Pandas / NumPy
* Flask (if used)
* Machine Learning (Logistic Regression)

---

## 📂 Project Structure

```
├── dataset/
├── model/
├── app.py
├── train_model.py
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

```bash
git clone https://github.com/Kamal762005/Web-Application-Firewall-using-ML.git
cd Web-Application-Firewall-using-ML
pip install -r requirements.txt
```

---

## ▶️ Usage

### Train Model

- jupyter notebook : run the file "Web Application Firewall .ipynb"

### Run Application

```bash
python Proxy_server.py
```
### Setup Proxy 

add the extension foxy proxy to the firefox and add the proxy as shown below

<img width="1454" height="477" alt="image" src="https://github.com/user-attachments/assets/ff7a0a66-3562-4da3-a3f0-34932f7d5803" />

after that navigate to any http based site and test it.

#### For Example

- demo.testfire.net
- testphp.vulnweb.com

## 📊 Model Details

* Algorithm: Logistic Regression
* Type: Supervised Learning
* Input: HTTP request features
* Output: Binary classification (Malicious / Normal)

---

## 📈 Future Improvements

* 🔄 Add Deep Learning models (LSTM / CNN)
* 🌐 Deploy as reverse proxy WAF
* 🧠 Use real-time adaptive learning
* 📡 Integrate with cloud platforms (AWS / Azure)
* 📊 Improve dataset diversity

---

