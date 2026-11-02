#ifndef CLASSIFIER_H
#define CLASSIFIER_H

class Classifier {
public:
    // Trained Decision Tree (scikit-learn, max_depth=4, trained via train_model.py)
    // Inputs: x[0]=Payload Size, x[1]=Battery Level, x[2]=Free Heap, x[3]=Priority
    // Output: 0 = ChaCha20, 1 = Ascon-128
    int predict(float *x) {
        if (x[1] <= 20.537577629089355f) {
            return 1; // Ascon-128
        } else {
            if (x[0] <= 104.15882873535156f) {
                return 1; // Ascon-128
            } else {
                if (x[1] <= 30.078043937683105f) {
                    if (x[3] <= 0.5f) {
                        return 0; // ChaCha20
                    } else {
                        return 1; // Ascon-128
                    }
                } else {
                    return 0; // ChaCha20
                }
            }
        }
    }
};

#endif