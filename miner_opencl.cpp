#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <nlohmann/json.hpp>
#include <random>
#include <ctime>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <cstring>         
#include <sys/socket.h>     
#include <arpa/inet.h>    
#include <netdb.h>          
#include <unistd.h>
#include <OpenCL/cl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using json = nlohmann::json;

std::string ADDRESS = "";  // wallet__address
const std::string PASSWORD= "password";
const std::string HOST = "solo.ckpool.org";




const int PORT = 3333;


std::mt19937 rng(static_cast<uint32_t>(std::time(nullptr)));
std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);

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

uint32_t  mine_gpu( const char * input_hex,  size_t global_size ,  size_t offset ){


    size_t input_len = strlen(input_hex);
    size_t output_nonce=0; 
    char* source = read_kernel_source("sha256.cl");

 
    
    cl_platform_id platform;
    cl_device_id device;
    cl_context context;
    cl_command_queue queue;
    cl_program program;
    cl_kernel kernel;
    cl_int err;
 
   
    err = clGetPlatformIDs(1, &platform, NULL);
    err |= clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, NULL);
 
   
    context = clCreateContext(NULL, 1, &device, NULL, NULL, &err);
    queue = clCreateCommandQueue(context, device, 0, &err);
 
  
    
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
 
   
    cl_mem input_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY ,input_len +1,NULL, &err);
    cl_mem output_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE, 65 , NULL, &err);
    cl_mem nonce_buffer = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(unsigned long) , NULL, &err);
 
    err = clEnqueueWriteBuffer(queue, input_buffer, CL_TRUE, 0, input_len * sizeof(const char)+1, input_hex, 0, NULL, NULL);
 
    clFinish(queue);
    
    
    err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &input_buffer);
    err |= clSetKernelArg(kernel, 1, sizeof(unsigned long), &input_len);
    err |= clSetKernelArg(kernel, 2, sizeof(cl_mem), &output_buffer);
    err |= clSetKernelArg(kernel, 3, sizeof(cl_mem), &nonce_buffer);
 
    if(err !=CL_SUCCESS){printf("Problem\n");}
 

  
    err = clEnqueueNDRangeKernel(queue, kernel, 1, &offset, &global_size, NULL, 0, NULL, NULL);
    clFinish(queue);
 
 
   
    char hash_output[65]={0};
    err = clEnqueueReadBuffer(queue, output_buffer, CL_TRUE, 0, 65, hash_output, 0, NULL, NULL);
    err = clEnqueueReadBuffer(queue, nonce_buffer, CL_TRUE, 0, sizeof(unsigned long), &output_nonce, 0, NULL, NULL);
   
    clFinish(queue);
    printf("SHA-256 hash: %s\n", hash_output);
 
    
    clReleaseMemObject(input_buffer);
    clReleaseMemObject(output_buffer);
    clReleaseKernel(kernel);
    clReleaseProgram(program);
    clReleaseCommandQueue(queue);
    clReleaseContext(context);
    free(source);
 
 
    return output_nonce;




}


bool read_file_to_string(const std::string& filename, std::string& content) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        content += line;  
    }

    file.close();
    return true;
}

bool write_string_to_file(const std::string& filename, const std::string& content) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return false;
    }

    file << content;  
    file.close();
    return true;
}




std::string sha256(const std::string& input) {
    
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    
    if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

   
    if (EVP_DigestUpdate(context, input.c_str(), input.size()) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

   
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    if (EVP_DigestFinal_ex(context, hash, &lengthOfHash) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

   
    EVP_MD_CTX_free(context);

   
    std::ostringstream ss;
     ss << std::uppercase; 
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

std::string to_little_endian(const std::string& input) {
    std::string output;
    for (size_t i = 0; i < input.length(); i += 2) {
        output = input.substr(i, 2) + output;
    }
    return output;
}


int connect_to_server(const std::string &host, int port) {
    int sockfd;
    struct addrinfo hints{}, *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        std::cerr << "getaddrinfo failed\n";
        return -1;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1) {
        std::cerr << "Socket creation failed\n";
        freeaddrinfo(res);
        return -1;
    }

    if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
        std::cerr << "Connection failed\n";
        close(sockfd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return sockfd;
}

void send_data(int sockfd, const std::vector<unsigned char> &data) {
    ssize_t bytes_sent = send(sockfd, reinterpret_cast<const char *>(data.data()), data.size(), 0);
    if (bytes_sent == -1) {
        std::cerr << "Send failed\n";
    } else {
        std::cout << "Sent " << bytes_sent << " bytes.\n";
    }
}

std::string receive_data(int sockfd) {
    char buffer[4096];
    std::string result;
    ssize_t n;

    while ((n = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[n] = '\0';
        result += buffer;
        if (n < sizeof(buffer) - 1)
            break;
    }

    if (n == -1) {
        std::cerr << "Receive failed\n";
    } else if (n == 0) {
        std::cout << "Connection closed by server.\n";
    }

    return result;
}

std::vector<unsigned char> string_to_byte_vector(const std::string& str) {
    std::vector<unsigned char> byte_vector;
    for (char c : str) {
        byte_vector.push_back(static_cast<unsigned char>(c));
    }
    return byte_vector;
}

std::string get_target( const std::string& nbits){


  std::string coefficient = nbits.substr(2);
  int exponent = stoi(nbits.substr(0, 2), nullptr, 16);
  size_t target_length = 64 - (exponent - 3) * 2;

  if (target_length < 0) {
   
    std::cerr << "Invalid target size!" << std::endl;
    return "";
 }

std::string target = coefficient + std::string((exponent - 3) * 2, '0');
target = target.insert(0, 64 - target.size(), '0');



 return target;



}


bool is_hash_valid(const std::string& hash, const std::string& target) {
  
    std::stringstream hash_stream, target_stream;
    unsigned long long hash_value, target_value;

    
    hash_stream << std::hex << hash;
    hash_stream >> hash_value;

    target_stream << std::hex << target;
    target_stream >> target_value;

  
    return hash_value < target_value;
}





std::string generate_nonce(uint32_t i) {


  //uint32_t random_number = dist(rng);

  
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << i;

    return ss.str();
}


int main() {



  
  bool unfound=true;
  int counter =0;
  std::string lowest_hash="";
  std::string t_hash="";

  read_file_to_string("address.txt", ADDRESS); 
  read_file_to_string("lowest_hash.txt", lowest_hash);

  std::cout<<"Wallet Address: "<<ADDRESS<<std::endl;

  rng.seed(static_cast<uint32_t>(std::time(nullptr)));

  
  while(unfound){

 

    
    int sockfd = connect_to_server(HOST, PORT);
    if (sockfd == -1) {
        return 1;
    }



    std::string subscribe_message_str = "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": []}\n";
 
    send_data(sockfd,  string_to_byte_vector(subscribe_message_str));

  

    std::string response = receive_data(sockfd);
   
    json json_response = json::parse(response);
    std::string extranonce1 = json_response["result"][1];
    int extranonce2_size = json_response["result"][2];

    std::cout << "Extranonce1: " << extranonce1 << "\nExtranonce2 Size: " << extranonce2_size << std::endl;

    std::string authorize_message= "{\"params\": [\""+ ADDRESS + "\", \"" + PASSWORD + "\"], \"id\": 2, \"method\": \"mining.authorize\"}\n";


    send_data(sockfd,  string_to_byte_vector(authorize_message));

    // Wait for 'mining.notify'
    std::string notify_response;
    while (notify_response.find("mining.notify") == std::string::npos) {
        notify_response = receive_data(sockfd);
    }


    json notify_json     = json::parse(notify_response);
    std::string job_id   = notify_json["params"][0];
    std::string prevhash = notify_json["params"][1];
    std::string coinb1   = notify_json["params"][2];
    std::string coinb2   = notify_json["params"][3];
    std::vector<std::string> merkle_branch = notify_json["params"][4];
    std::string version  = notify_json["params"][5];
    std::string nbits    = notify_json["params"][6];
    std::string ntime    = notify_json["params"][7];

    std::cout<<"Job_ID: "    << job_id  <<std::endl;
    std::cout<<"Prev_Hash: " << prevhash<<std::endl;
    std::cout<<"Coin_B1: "   << coinb1  << std::endl;
    std::cout<<"Coin_B2: "   << coinb2  << std::endl;
 
    std::cout<<"Version: "   << version << std::endl;
    std::cout<<"N_Bits: "    << nbits   << std::endl;
    std::cout<<"N_Time: "    << ntime   << std::endl;
    std::cout<<std::endl;
    std::cout<<"Mining...unit "<<counter++<<std::endl;
    std::cout<<"Lowest Hash achieved so far: "<<lowest_hash<<std::endl;
    std::cout<<"Target Hash                : "<<t_hash<<std::endl; 

    /* Calculate target
    std::string target = nbits.substr(2) + std::string((stoi(nbits.substr(0, 2), nullptr, 16) - 3) * 2, '0');
    target = target.insert(0, 64 - target.size(), '0');
   */

    std::string target = get_target(nbits);
  

    std::string extranonce2(extranonce2_size * 2, '0');


    std::string coinbase = coinb1 + extranonce1 + extranonce2 + coinb2;
    std::string coinbase_hash_bin = sha256(sha256(coinbase));



    std::string merkle_root = coinbase_hash_bin;
    for (const auto& branch : merkle_branch) {
        merkle_root = sha256(sha256(merkle_root + branch));
    }

    merkle_root = to_little_endian(merkle_root);


      std::string partial_block_header = version + prevhash + merkle_root + nbits + ntime;

      uint32_t n = gpu_mine(partial_block_header.c_str(), 1000, dist(rng) ); 

      std::string nonce = generate_nonce(n);

      std::string blockheader = partial_block_header + nonce + 
                              "000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000";

     
    std::string hash = sha256(sha256(blockheader));
    std::cout<<"GPU hash: "<<hash<<std::endl;

    std::transform(hash.begin(), hash.end(), hash.begin(), ::toupper);
    std::transform(target.begin(), target.end(), target.begin(), ::toupper);

    t_hash = target; 

    
    if (hash < target ) {
      
        std::cout << "Success! Submitting the result..." << std::endl;
	
        std::string submit_message = "{\"params\": [\"" +
	  ADDRESS + "\", \"" +
	  job_id + "\", \"" +
	  extranonce2 + "\", \"" +
	  ntime + "\", \"" +
	  nonce + "\"], \"id\": 1, \"method\": \"mining.submit\"}\n";

	send_data(sockfd, string_to_byte_vector(submit_message));
	
        std::string submit_response = receive_data(sockfd);
	
        std::cout << "Submit Response: " << submit_response << std::endl;
	
	unfound=false;
	
    } else if(lowest_hash.empty()) {

      lowest_hash = hash;
     
     
    } else if(hash < lowest_hash){

      lowest_hash = hash;
      

      write_string_to_file("lowest_hash.txt", lowest_hash);
      
    }
  
     close(sockfd);
  }

    return 0;
}
