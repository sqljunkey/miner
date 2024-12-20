#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <nlohmann/json.hpp>
#include <random>
#include <ctime>
#include <iomanip>
#include <omp.h>
#include <fstream>
#include <algorithm>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

using json = nlohmann::json;

std::string ADDRESS = "";  // wallet__address
const std::string PASSWORD= "password";
const std::string HOST = "solo.ckpool.org";




const int PORT = 3333;


std::mt19937 rng(static_cast<uint32_t>(std::time(nullptr)));
std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);


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




__device__ unsigned int rotate_right(unsigned int value, unsigned int shift) {
    return (value >> shift) | (value << (32 - shift));
}

__device__ void sha256_transform(const unsigned char *data, unsigned char *hash) {
    unsigned int K[64] = { /* SHA256 constants */ };
    unsigned int W[64], a, b, c, d, e, f, g, h;
    
    // Initial hash values (SHA-256 standard values)
    a = 0x6a09e667;
    b = 0xbb67ae85;
    c = 0x3c6ef372;
    d = 0xa54ff53a;
    e = 0x510e527f;
    f = 0x9b05688c;
    g = 0x1f83d9ab;
    h = 0x5be0cd19;

    // Message preparation (copy into W[0..15])
    for (int i = 0; i < 16; ++i) {
        W[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) | (data[i * 4 + 2] << 8) | data[i * 4 + 3];
    }

    // SHA-256 main loop
    for (int i = 16; i < 64; ++i) {
        unsigned int s0 = rotate_right(W[i - 15], 7) ^ rotate_right(W[i - 15], 18) ^ (W[i - 15] >> 3);
        unsigned int s1 = rotate_right(W[i - 2], 17) ^ rotate_right(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    // Main SHA-256 loop
    for (int i = 0; i < 64; ++i) {
        unsigned int temp1 = h + (rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + W[i];
        unsigned int temp2 = (rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // Add the hash values to the current hash
    hash[0] = (a >> 24) & 0xff;
    hash[1] = (a >> 16) & 0xff;
    hash[2] = (a >> 8) & 0xff;
    hash[3] = a & 0xff;

    // Repeat the same for all hash values (b, c, ..., h)
    hash[4] = (b >> 24) & 0xff;
    hash[5] = (b >> 16) & 0xff;
    hash[6] = (b >> 8) & 0xff;
    hash[7] = b & 0xff;

    hash[8] = (c >> 24) & 0xff;
    hash[9] = (c >> 16) & 0xff;
    hash[10] = (c >> 8) & 0xff;
    hash[11] = c & 0xff;

    hash[12] = (d >> 24) & 0xff;
    hash[13] = (d >> 16) & 0xff;
    hash[14] = (d >> 8) & 0xff;
    hash[15] = d & 0xff;

    hash[16] = (e >> 24) & 0xff;
    hash[17] = (e >> 16) & 0xff;
    hash[18] = (e >> 8) & 0xff;
    hash[19] = e & 0xff;

    hash[20] = (f >> 24) & 0xff;
    hash[21] = (f >> 16) & 0xff;
    hash[22] = (f >> 8) & 0xff;
    hash[23] = f & 0xff;

    hash[24] = (g >> 24) & 0xff;
    hash[25] = (g >> 16) & 0xff;
    hash[26] = (g >> 8) & 0xff;
    hash[27] = g & 0xff;

    hash[28] = (h >> 24) & 0xff;
    hash[29] = (h >> 16) & 0xff;
    hash[30] = (h >> 8) & 0xff;
    hash[31] = h & 0xff;
}

__global__ void sha256_kernel(const unsigned char *data, unsigned char *hash) {
    sha256_transform(data, hash);
}

std::string cuda_sha256(const std::string& input) {
    std::vector<unsigned char> input_vec(input.begin(), input.end());
    unsigned char *d_input, *d_output;

    // Allocate device memory for input and output
    cudaMalloc((void**)&d_input, input_vec.size() * sizeof(unsigned char));
    cudaMalloc((void**)&d_output, 32 * sizeof(unsigned char));  // SHA-256 output size is 32 bytes

    // Copy input data to device
    cudaMemcpy(d_input, input_vec.data(), input_vec.size() * sizeof(unsigned char), cudaMemcpyHostToDevice);

    // Launch kernel
    sha256_kernel<<<1, 1>>>(d_input, d_output);

    // Ensure the kernel has finished
    cudaDeviceSynchronize();

    // Prepare output vector and copy result back to host
    std::vector<unsigned char> output(32);  // SHA-256 output is 32 bytes
    cudaMemcpy(output.data(), d_output, 32 * sizeof(unsigned char), cudaMemcpyDeviceToHost);

    // Free device memory
    cudaFree(d_input);
    cudaFree(d_output);

    // Convert output to hexadecimal string
    std::ostringstream oss;
    for (unsigned char byte : output) {
        oss << std::setw(2) << std::setfill('0') << std::hex << (int)byte;
    }

    return oss.str();
}

std::string to_little_endian(const std::string& input) {
    std::string output;
    for (size_t i = 0; i < input.length(); i += 2) {
        output = input.substr(i, 2) + output;
    }
    return output;
}

bool init_winsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
        return false;
    }
    return true;
}


void cleanup_winsock() {
    WSACleanup();
}


SOCKET connect_to_server(const std::string& host, int port) {
    SOCKET sockfd = INVALID_SOCKET;

    struct addrinfo* result = NULL, hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int res = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result);
    if (res != 0) {
        std::cerr << "getaddrinfo failed: " << res << std::endl;
        cleanup_winsock();
        return INVALID_SOCKET;
    }

    sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sockfd == INVALID_SOCKET) {
        std::cerr << "Error creating socket." << std::endl;
        freeaddrinfo(result);
        cleanup_winsock();
        return INVALID_SOCKET;
    }

    res = connect(sockfd, result->ai_addr, (int)result->ai_addrlen);
    if (res == SOCKET_ERROR) {
        std::cerr << "Error connecting to server." << std::endl;
        closesocket(sockfd);
        freeaddrinfo(result);
        cleanup_winsock();
        return INVALID_SOCKET;
    }

    freeaddrinfo(result);
    return sockfd;
}

void send_data(SOCKET sockfd, const std::vector<unsigned char>& data) {
    int bytes_sent = send(sockfd, reinterpret_cast<const char*>(data.data()), data.size(), 0);
    if (bytes_sent == SOCKET_ERROR) {
        std::cerr << "Send failed with error: " << WSAGetLastError() << std::endl;
    } else {
        std::cout << "Sent " << bytes_sent << " bytes." << std::endl;
    }
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


std::string receive_data(SOCKET sockfd) {
    char buffer[4096];
    std::string result;
    int n;

    while ((n = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
      std::cout<<result<<std::endl;
        buffer[n] = '\0';  
        result += buffer; 
        if (n < sizeof(buffer) - 1) break; 
    }

    if (n == SOCKET_ERROR) {
        std::cerr << "Receive failed with error: " << WSAGetLastError() << std::endl;
    } else if (n == 0) {
        std::cout << "Connection closed by server." << std::endl;
    } else {
      //std::cout << "Received " << result.size() << " bytes: " << result << std::endl;
    }

    return result;
}


std::string generate_nonce() {


    uint32_t random_number = dist(rng);

  
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << random_number;

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

 

    
    if (!init_winsock()) {
        return 1;
    }

  

    SOCKET sockfd = connect_to_server(HOST, PORT);
    if (sockfd == INVALID_SOCKET) {
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
    std::string coinbase_hash_bin = cuda_sha256(cuda_sha256(coinbase));



    std::string merkle_root = coinbase_hash_bin;
    for (const auto& branch : merkle_branch) {
      merkle_root = cuda_sha256(cuda_sha256(merkle_root + branch));
    }

    merkle_root = to_little_endian(merkle_root);


    #pragma omp parallel for schedule(dynamic) 
    for(int i =0; i < 100000000; i++){

      std::string nonce = generate_nonce();

      std::string blockheader = version + prevhash + merkle_root + nbits + ntime + nonce + 
                              "000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000";


      std::string hash = cuda_sha256(cuda_sha256(blockheader));

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
  }

    closesocket(sockfd);
    cleanup_winsock();
  }

    return 0;
}
