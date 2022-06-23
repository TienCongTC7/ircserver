#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "shared_func.h"
#include "json.h"

char message[1024];
char encryp[1024]; // to store encryp msg
char decryp[1024]; // to store decryp msg
long int temp[1024]; // do something
int e; // public key
int d; // private key
int m; // m = p * q
static const char use[51] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ!@$&*()_+=-0987654321|?.,";

// a ^ b mod n
int Calculate(int a, int b, int n)
{
    long long x = 1, y = a;
    while (b > 0)
    {
        if (b % 2 == 1)
        {
            x = (x * y) % n; // multiplying with base
        }
        y = (y * y) % n; // squaring the base
        b /= 2;
    }
    return x % n;
}
int gcd(int a, int b)
{
    if (b == 0)
        return a;
    a %= b;
    return gcd(b, a);
}

int coprime(int a, int b)
{

    if (gcd(a, b) == 1)
        return 1; // true
    else
        return 2; // false
}

void encrypt()
{
    long int pt1, pt2; // pointer1 , pointer2
    long int len = strlen(message);
    int i = 0;
    while (i != len)
    {
        pt1 = decryp[i];
        pt1 = pt1 - 96;
        int k = Calculate(pt1, e, m); // pt1 ^ e mod m
        temp[i] = k;
        pt2 = k + 9696969696;
        // The correct form is: encryp[i] = ct; (But json can not encode it so we let encrypt1 = 'some string')
        encryp[i] = '$';
        i++;
    }
    encryp[i] = -1;
    for(int i=0 ; message[i] != '\0'; i++)
    {
        message[i] = encryp[i]; 
    }
} 

void decrypt()
{
    long int pt1, pt2; // pointer1, pointer2
    int i = 0;
    while (decryp[i] != -1)
    {
        pt2 = temp[i];
        int k = Calculate(pt2, d, m); // ct ^ d mod m
        pt1 = k + 96;
        decryp[i] = pt1;
        i++;
    }
    decryp[i] = -1;
    for(int i=0; message[i] != '\0'; i++)
    {
        message[i] = decryp[i];
    }
}

void Gen_key()
{
    int p = 7;
    int q = 13;
    long int n = (p-1) * (q-1);
    m = p * q;
    for (int i = 2; i < n; i++)
    {
        for (int j = 2; j < 10; j++)
        {
            if (coprime(i, n) == 1 && coprime(i, m) == 1 && j != i && (j * i) % n == 1)
            {
                d = i; // found private key
                e = j; // found public key
                break;
            }
        }
    }
}


void RSA()
{
    for (int i = 0; message[i] != '\0'; i++)
    {
        decryp[i] = message[i];
    }
}


void handle_request(char *request, int senderfd)
{
    /*
    This functions receive a request to encrypt1 or decrypt
    and then send back the result
    */
    //printf("\nRequest: %s\n", request);

    // Decode the request from string to json
    JsonNode *request_json = json_decode(request);
    int receiver = json_find_member(request_json, "receiver")->number_;
    char *method = json_find_member(request_json, "method")->string_;
    char *request_message = json_find_member(request_json, "message")->string_;

    // Encrypt the message
    // TODO: Check if method is ENCRYPT => Encrypt the message
    // TODO: Check if method is DECRYPT => Decrypt the message
    int compare;
    char *check = "ENCRYPT";
    compare = strcmp(check,method);
    if(compare == 0)
    {
        RSA();
        Gen_key();
        encrypt();
        char *response_message = message;

        // Create the response payload
        JsonNode *response_json = json_mkobject();
        JsonNode *client_fd_json = json_mknumber(receiver);
        JsonNode *method_json = json_mkstring(method);
        JsonNode *message_json = json_mkstring(response_message);
        json_append_member(response_json, "receiver", client_fd_json);
        json_append_member(response_json, "method", method_json);
        json_append_member(response_json, "message", message_json);

        // Encode the json response to string
        char *response_buffer = json_encode(response_json);
        printf("Response: %s\n", response_buffer);

        // Send back the encrypted or decrypted payload
        send(senderfd, response_buffer, strlen(response_buffer) + 1, 0);
    }
    else
    {
        decrypt();
        char *response_message = message;

        // Create the response payload
        JsonNode *response_json = json_mkobject();
        JsonNode *client_fd_json = json_mknumber(receiver);
        JsonNode *method_json = json_mkstring(method);
        JsonNode *message_json = json_mkstring(response_message);
        json_append_member(response_json, "receiver", client_fd_json);
        json_append_member(response_json, "method", method_json);
        json_append_member(response_json, "message", message_json);

        // Encode the json response to string
        char *response_buffer = json_encode(response_json);
        printf("Response: %s\n", response_buffer);

        // Send back the encrypted or decrypted payload
        send(senderfd, response_buffer, strlen(response_buffer) + 1, 0);
    }

    
}