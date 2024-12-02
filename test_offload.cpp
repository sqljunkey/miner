#include <iostream>
#include <omp.h>
#include <vector>

int main() {
    const int N = 1000;                // Array size
    std::vector<float> array(N, 1.0); // Initialize array with 1.0
    std::vector<float> result(N, 0);  // To store results

    // Offload computation to GPU
    #pragma omp target teams distribute parallel for map(to: array[0:N]) map(from: result[0:N])
    for (int i = 0; i < N; ++i) {
        result[i] = array[i] * array[i]; // Compute square
    }

    // Verify results on the host
    bool success = true;
    for (int i = 0; i < N; ++i) {
        if (result[i] != 1.0) {
            success = false;
            break;
        }
    }

    if (success) {
        std::cout << "Test Passed! All elements squared correctly." << std::endl;
    } else {
        std::cout << "Test Failed! Incorrect computation." << std::endl;
    }

    return 0;
}
