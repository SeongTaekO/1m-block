#include <string.h>
#include "quick_sort.h"

// 퀵 정렬 구현
void quick_sort(char **arr, int left, int right) {
    if (left < right) {
        char *pivot = arr[right];
        int i = left - 1;

        for (int j = left; j < right; ++j) {
            if (strcmp(arr[j], pivot) <= 0) {
                ++i;
                char *temp = arr[i];
                arr[i] = arr[j];
                arr[j] = temp;
            }
        }

        char *temp = arr[i + 1];
        arr[i + 1] = arr[right];
        arr[right] = temp;

        int pivot_index = i + 1;

        quick_sort(arr, left, pivot_index - 1);
        quick_sort(arr, pivot_index + 1, right);
    }
}

