import numpy as np
from sklearn.tree import DecisionTreeClassifier

np.random.seed(42)
X_train = []
y_train = []

for _ in range(500):
    payload = np.random.uniform(16, 2000)
    battery = np.random.uniform(1, 100)
    heap = np.random.uniform(50000, 200000)
    priority = np.random.choice([0.0, 1.0])

    if battery < 20 or payload < 100:
        decision = 1  # Ascon
    elif payload > 1000 and battery > 50:
        decision = 0  # ChaCha20
    elif priority == 1.0 and battery < 30:
        decision = 1  # Ascon
    else:
        decision = 0  # ChaCha20

    X_train.append([payload, battery, heap, priority])
    y_train.append(decision)

X_train = np.array(X_train)
y_train = np.array(y_train)

clf = DecisionTreeClassifier(max_depth=4, random_state=42)
clf.fit(X_train, y_train)

print("Training Accuracy:", clf.score(X_train, y_train))
from micromlgen import port

print("\n" + "="*50)
print("C++ Header Code:")
print("="*50 + "\n")
print(port(clf))