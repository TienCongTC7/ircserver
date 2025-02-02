#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "shared_func.h"
#include "json.h"

void broadcast(char *message, int *clientfds, int encryptfd, int authfd, int senderfd)
{
    /*
    This function broadcast a message to all clients except for
    the sender, the encryption server and the authentication server
    */

    // Loop through each file descriptor
    for (int i = 0; i < MAX_CLIENT; i++)
    {
        int clientfd = clientfds[i];
        // Send the message if file the descriptor belongs to a valid client
        if (clientfd != 0 && clientfd != encryptfd && clientfd != authfd && clientfd != senderfd)
        {
            send(clientfd, message, strlen(message) + 1, 0);
        }
    }
}

void handle_authentication()
{
    /*
    This function handle the responses from the authentication server and send back to clients
    */
}

void handle_client_request(char *payload, int encryptfd, int clientfd)
{
    /*
    This function take the login or register request from the client and send to authentication server.

    Incoming payload structure:
    {
        "method": method,
        "username": username,
        "password": password
    }
    - method is either LOGIN or REGISTER
    - username is the username of the client
    - password is the password of the client
    */
    JsonNode *payload_json = json_decode(payload);
    char *method = json_find_member(payload_json, "method")->string_;
    char *message = json_find_member(payload_json, "message")->string_;
    // printf("Decrypted message: %s\n", message);
    // TODO: Creat the payload and send to authentication server
}

void handle_encryption_response(char *payload, int *clientfds, int encryptfd, int authfd)
{
    /*
    This function handle the payload received from the encryption server.
    The method of the incoming method can either be:
    - DECRYPT => The payload is the response of a DECRYPT request, contains the login or register message to send to authentication server
    - ENCRYPT => The payload is the response of a ENCRYPT request, contains encrypted payload to send to the client
    */

    // Decode the incoming payload
    JsonNode *payload_json = json_decode(payload);
    int receiver = json_find_member(payload_json, "receiver")->number_;
    char *method = json_find_member(payload_json, "method")->string_;
    char *message = json_find_member(payload_json, "message")->string_;

    if (strcmp(method, "DECRYPT") == 0)
    {
        // Client request to login or register
        handle_client_request(message, encryptfd, receiver);
    }
    else if (strcmp(method, "ENCRYPT") == 0)
    {
        // The encrypted payload of the login or register result
        // TODO: Create the payload and send to the receiver
    }
}

void server_handler(char *payload, int *clientfds, int senderfd, int authfd, int encryptfd)
{
    /*
    This function is the main function to handle all incoming requests to IRC server.
    Request can come from:
    - Authentication server: Unencrypted, login or register result
    - Encryption server: Unencrypted, encrypted or decrypted result
    - Client: Encrypted, can have the method of:
        + BROADCAST => Broadcast this message to all other clients
        + UNICAST => Send this message to encryption server to decrypt
    */
    // printf("Received payload from %d: %s", senderfd, payload);
    JsonNode *received_payload = json_decode(payload);
    char *method = json_find_member(received_payload, "method")->string_;

    if (senderfd == authfd)
    {
        /* Payload comes from authentication server */
    }
    else if (senderfd == encryptfd)
    {
        /* Payload comes from authentication server */
        handle_encryption_response(payload, clientfds, encryptfd, authfd);
    }
    else
    {
        /* Encrypted payload comes from clients */
        if (strcmp(method, "BROADCAST") == 0)
        {
            printf("Broadcast payload: %s\n", payload);
            broadcast(payload, clientfds, encryptfd, authfd, senderfd);
        }
        else if (strcmp(method, "UNICAST") == 0)
        {
            // TODO: Create the payload and send a decrypt request to the decryption server
            char *encrypted_message = json_find_member(received_payload, "message")->string_;
            // printf("Encrypted message: %s\n", encrypted_message);
        }
    }
}
