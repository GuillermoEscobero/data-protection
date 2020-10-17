#!/usr/bin/expect -f

set timeout -1

spawn ./tests.sh

while { 1 } {
    expect {
        "Enter passphrase*" { send -- "1234567890123456\n" }
        "DONE" { exit }
    }
}

expect eof
