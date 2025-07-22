#!/bin/bash
# Handler script for private chat connections
# Sends password prompt and validates before opening chat

# Notify client password is required
echo "PASSWORD_REQUIRED"
read -r client_pass || exit 1
if [ "$client_pass" = "$CHAT_PASSWORD" ]; then
    echo "Access granted. Start chatting."
    exec cat
else
    echo "Wrong password"
fi
