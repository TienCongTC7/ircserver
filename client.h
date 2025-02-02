#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include "shared_func.h"
#include "json.h"

void handle_send_request(int encryptfd, char *message, char *clientid)
{
    /*
    This function take user's input, create a payload and send the payload to the encryption server.

    Payload structure:
    {
        "receiver": receiver,
        "method": "ENCRYPT",
        "message": message
    }
    - receiver is either 0 or 1. 0 stands for BROADCAST method, 1 stands for UNICAST method.
    - message: depends on the users'commands. Can be username, password to login & register, or message content to send to others.
    */

    // TODO: Parse message to check for register or login command

    // TODO:
    // => Create register payload
    // => Send to encryption server

    // TODO: Handle login commands
    // => Create login payload
    // => Send to encryption server

    // Create the payload for sending message to others
    JsonNode *payload_json = json_mkobject();                    // {}
    JsonNode *method_json = json_mkstring("MESSAGE");            // "MESSAGE"
    JsonNode *username_json = json_mkstring("admin");            // "admin"
    JsonNode *message_json = json_mkstring(message);             // "randomtext"
    json_append_member(payload_json, "method", method_json);     // {"method": "MESSAGE"}
    json_append_member(payload_json, "username", username_json); // {"method": "MESSAGE", "username": "admin"}
    json_append_member(payload_json, "message", message_json);   // {"method": "MESSAGE", "username": "admin", "message": "randomtext"}

    // Send the payload to encrypt server
    char *payload_buffer = json_encode(payload_json);
    // printf("Raw request: %s\n", payload_buffer);
    request_encryption_server("ENCRYPT", payload_buffer, encryptfd, 0);
}

void handle_server_response(char *payload, int encryptfd)
{
    /*
    This function take the payload from the
    IRC server and send to the encryption server
    */

    // Extract the encrypted message from the payload
    JsonNode *payload_json = json_decode(payload);
    char *message = json_find_member(payload_json, "message")->string_;
    // printf("Encrypted message: %s\n", message);

    // Call this function to send the message to the encryption server
    request_encryption_server("DECRYPT", message, encryptfd, 0);
}

void handle_encryption_response(char *payload, int ircfd)
{
    /*
    This function handle the payload received from the encryption server.
    The method of the incoming method can either be:
    - DECRYPT => The payload is the response of a DECRYPT request, contains the message to print
    - ENCRYPT => The payload is the response of a ENCRYPT request, contains encrypted payload to send to IRC server
    */

    // Decode the payload to json
    JsonNode *payload_json = json_decode(payload);
    int receiver = json_find_member(payload_json, "receiver")->number_;
    char *method = json_find_member(payload_json, "method")->string_;
    char *message = json_find_member(payload_json, "message")->string_;

    // Check if method is ENCRYPT
    if (strcmp(method, "ENCRYPT") == 0)
    {
        // Make the outgoing payload
        JsonNode *outgoing_payload = json_mkobject();
        char *outgoing_method = (receiver == 0) ? "BROADCAST" : "UNICAST";
        JsonNode *method_json = json_mkstring(outgoing_method);
        JsonNode *message_json = json_mkstring(message);
        json_append_member(outgoing_payload, "method", method_json);
        json_append_member(outgoing_payload, "message", message_json);

        // Send the outgoing payload to IRC server
        char *buffer = json_encode(outgoing_payload);
        send(ircfd, buffer, strlen(buffer) + 1, 0);
    }
    //  Otherwise if method is DECRYPT
    else if (strcmp(method, "DECRYPT") == 0)
    {
        // Decode the incoming message into json
        JsonNode *message_json = json_decode(message);
        // Extract the username and content
        char *username = json_find_member(message_json, "username")->string_;
        char *message_content = json_find_member(message_json, "message")->string_;
        // Display the received message to stdout
        printf("\r%s: %s> ", username, message_content);
    }
}