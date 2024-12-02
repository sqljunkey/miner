#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <OpenCL/cl.h>
 
// Read the OpenCL kernel file into a string
char* read_kernel_source(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open kernel file");
        exit(1);
    }
 
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    rewind(file);
 
    char* source = (char*)malloc(size + 1);
    fread(source, 1, size, file);
    source[size] = '\0';
    fclose(file);
 
    return source;
}
 
int main() {
    const char* kernel_file = "sha256.cl";
    const char* input_hex = "68656c6c6f20776f726c64"; // "hello world" in hex
    size_t input_len = strlen(input_hex);
 
 
 
    // OpenCL setup
    cl_platform_id platform;
    cl_device_id device;
    cl_context context;
    cl_command_queue queue;
    cl_program program;
    cl_kernel kernel;
    cl_int err;
 
    // Get platform and device
    err = clGetPlatformIDs(1, &platform, NULL);
    err |= clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, NULL);
 
    // Create context and command queue
    context = clCreateContext(NULL, 1, &device, NULL, NULL, &err);
    queue = clCreateCommandQueue(context, device, 0, &err);
 
    // Read and build the kernel
    char* source = read_kernel_source(kernel_file);
    program = clCreateProgramWithSource(context, 1, (const char**)&source, NULL, &err);
    err = clBuildProgram(program, 1, &device, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t log_size;
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
        char* log = (char*)malloc(log_size);
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, log_size, log, NULL);
        printf("Build log:\n%s\n", log);
        free(log);
        exit(1);
    }
 
    kernel = clCreateKernel(program, "sha256_kernel", &err);
 
    // Create buffers
    cl_mem input_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY ,input_len +1,NULL, &err);
    cl_mem output_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE, 65 , NULL, &err);
 
    err = clEnqueueWriteBuffer(queue, input_buffer, CL_TRUE, 0, input_len * sizeof(const char)+1, input_hex, 0, NULL, NULL);
 
    clFinish(queue);
    // Set kernel arguments
    err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &input_buffer);
    err |= clSetKernelArg(kernel, 1, sizeof(unsigned long), &input_len);
    err |= clSetKernelArg(kernel, 2, sizeof(cl_mem), &output_buffer);
 
    if(err !=CL_SUCCESS){printf("Problem\n");}
 
    // Execute the kernel
    size_t global_size = 1000000000;
    err = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &global_size, NULL, 0, NULL, NULL);
    clFinish(queue);
 
    // Read and print the output
    char hash_output[65] = {0};
 
    err = clEnqueueReadBuffer(queue, output_buffer, CL_TRUE, 0, 65, hash_output, 0, NULL, NULL);
    clFinish(queue);
    printf("SHA-256 hash: %s\n", hash_output);
 
    // Cleanup
    clReleaseMemObject(input_buffer);
    clReleaseMemObject(output_buffer);
    clReleaseKernel(kernel);
    clReleaseProgram(program);
    clReleaseCommandQueue(queue);
    clReleaseContext(context);
    free(source);
 
 
    return 0;
}
