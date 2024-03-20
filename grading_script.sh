#!/bin/bash

readonly bin="$(realpath ${1:-.})"

PROJECT_PATH=$(pwd)


readonly wd="$(mktemp -d)"
readonly basedir="$(realpath "$(dirname "$0")")"
cp "$basedir"/plaintext* "$wd"
cd "$wd"

LIMIT=500
limit() {
  rm -f STDOUT STDERR
  mkfifo STDOUT
  mkfifo STDERR
  head -c$LIMIT < STDOUT >&1 &
  head -c$LIMIT < STDERR >&2 &
  timeout -s9 5 "$@" 1>STDOUT 2>STDERR
}


#Record the ports passed in
encport=$((RANDOM % 60000 + 1025))
decport=$((RANDOM % 60000 + 1025))

#Run the daemons
# "${bin}"/enc_server $encport &>/dev/null &
# "${bin}"/dec_server $decport &>/dev/null &
cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin enc_server -- $encport &>/dev/null &
cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin dec_server -- $decport &>/dev/null &

sleep 1

pts=0
tot=0
echo '#-----------------------------------------'
echo '#START OF GRADING SCRIPT'

cleanup() {
#Clean up
echo
echo
echo '#-----------------------------------------'
echo '#SCRIPT COMPLETE'
echo $pts / $tot
rm -rf "$wd"
}

cleanupkilled() {
#Clean up
echo
echo 
echo '#-----------------------------------------'
echo '#It appears your program killed/crashed/exited...'
echo '#-----------------------------------------'
echo '#SCRIPT COMPLETE'
echo $pts / $tot
rm -rf "$wd"
}

trap cleanupkilled SIGPIPE SIGQUIT SIGABRT SIGTERM SIGINT SIGSEGV

trap cleanup EXIT

echo '#keygen 20 > key20'
limit cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin keygen -- 20 > key20
tput bold; tput setaf 4; echo -n "#5 POINTS:"; tput sgr0; echo " key20 must exist"
((tot+=5))
if [ -s key20 ]
then 
        echo 'key20 exists!'
        ((pts += 5))
else 
        echo 'key20 DOES NOT EXIST'
fi 
echo
echo "#-----------------------------------------"
tput bold; tput setaf 4; echo -n "#5 POINTS:"; tput sgr0; echo " Number of characters in key20, should be 21:"
((tot+=5))
count=$(wc -m <key20)
echo $count key20
if [ $count -eq 21 ]
then
        echo "Looks good!"
        ((pts += 5))
else
        echo "Looks not good :("
fi
echo
echo "#-----------------------------------------"
echo '#keygen 70000 > key70000'
LIMIT=100000
limit cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin keygen -- 70000 > key70000
LIMIT=500
tput bold; tput setaf 4; echo -n "#5 POINTS:"; tput sgr0; echo " Number of characters in key70000, should be 70001:"
((tot+=5))
count=$(wc -m < key70000)
echo $count key70000
if [ $count  -eq 70001 ]
then
        echo "Looks good!"
        ((pts += 5))
else
        echo "Looks not good :("
fi

echo "#-----------------------------------------"
echo "Generating keys using built-in keygen for remaining tests"
(shuf -n 700000 -re {A..Z} ' ' | tr -d '\n'; echo;) > key70000
(shuf -n 20 -re {A..Z} ' ' | tr -d '\n'; echo;) > key20

echo
echo "#-----------------------------------------"
echo '#enc_client plaintext1 key20 $encport'
tput bold; tput setaf 4; echo -n "#10 POINTS:"; tput sgr0; echo " Should return error about too-short key"
((tot+=10))
msg=$(limit cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin enc_client -- plaintext1 key20 $encport 3>&1 1>&2 2>&3 3>&-)
printf 'stderr: %s\n' "$msg"
if [ ! -z "$msg" ]
then
        echo "Looks good!"
        ((pts += 10))
else
        echo "No error message?"
fi
echo
echo "#-----------------------------------------"
echo '#enc_client plaintext1 key70000 $encport'
tput bold; tput setaf 4; echo -n "#20 POINTS:"; tput sgr0; echo " Should return encrypted version of plaintext1"
((tot+=20))
limit cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin enc_client -- plaintext1 key70000 $encport | tee ciphertext1 | paste 
echo
echo '#-----------------------------------------'
echo '#enc_client plaintext1 key70000 $encport > ciphertext1'
tput bold; tput setaf 4; echo -n "#10 POINTS:"; tput sgr0; echo " ciphertext1 must exist"
((tot+=10))
if [ -s ciphertext1 ]; then echo 'ciphertext1 exists!'; ((pts+=10)); else echo 'ciphertext1 DOES NOT EXIST'; fi 
echo
echo '#-----------------------------------------'
tput bold; tput setaf 4; echo -n '#10 POINTS:'; tput sgr0; echo ' ciphertext1 must be same number of chars as source'
((tot+=10))
echo '#wc -m plaintext1'
wc -m plaintext1
echo '#Should be same: wc -m ciphertext1'
wc -m ciphertext1
if [ "$(wc -m <plaintext1)" -eq "$(wc -m <ciphertext1)" ]
then
        echo "looks good"
        ((pts += 10))
else
        echo "Doesn't match :("
fi
echo
echo '#-----------------------------------------'
tput bold; tput setaf 4; echo -n '#5 POINTS:'; tput sgr0; echo ' ciphertext1 should look encrypted'
((tot+=5))
if [ -s ciphertext1 ] && ! grep '[^A-Z ]' ciphertext1 &>/dev/null
then
        echo "Looks encrypted to me!"
        ((pts+=25))
else
        echo "Doesn't look right.."
fi
echo
echo '#-----------------------------------------'
echo '#dec_client ciphertext1 key70000 $encport'
tput bold; tput setaf 4; echo -n '#5 POINTS:'; tput sgr0; echo ' Should fail giving error that dec_client cannot use enc_server'
((tot+=5))
msg=$(limit cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin dec_client -- ciphertext1 key70000 $encport 3>&1 1>&2 2>&3 3>&-)
printf '%s\n' "$msg"
if [ ! -z "$msg" ]
then
        echo "Looks good!"
        ((pts += 5))
else
        echo "No error message?"
fi
echo
echo '#-----------------------------------------'
tput bold; tput setaf 4; echo -n '#20 POINTS:'; tput sgr0; echo ' should return decrypted ciphertext1 that matches source'
((tot+=20))
echo '#cat plaintext1'
cat plaintext1
echo '#dec_client ciphertext1 key70000 $decport'
limit cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin dec_client -- ciphertext1 key70000 $decport | tee output

if cmp plaintext1 output
then
        echo "Matches"
        ((pts += 20))
else
        echo "Doesn't match"
fi
echo
echo '#-----------------------------------------'
echo '#dec_client ciphertext1 key70000 $decport > plaintext1_a'
limit cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin dec_client -- ciphertext1 key70000 $decport > plaintext1_a
tput bold; tput setaf 4; echo -n "#10 POINTS:"; tput sgr0; echo " plaintext1_a must exist"
((tot+=10))
if [ -s plaintext1_a ]; then echo 'plaintext1_a exists!'; ((pts+=10)); else echo 'plaintext1_a DOES NOT EXIST'; fi
echo
echo '#-----------------------------------------'
echo '#cmp plaintext1 plaintext1_a'
tput bold; tput setaf 4; echo -n '#5 POINTS:'; tput sgr0; echo ' plaintext1 must be the same as plaintext1_a:'
((tot+=5))
echo '#echo $? should be == 0, which means the cmp succeeded!'
cmp plaintext1 plaintext1_a
ret=$?
echo $ret
if [ $ret -eq 0 ]
then
        ((pts += 5))
        echo "looks good"
else
        echo "Not 0"
fi
echo
echo '#-----------------------------------------'
tput bold; tput setaf 4; echo -n '#20 POINTS:'; tput sgr0; echo ' concurrent test of encryption - look for 4 properly-sized ciphertext# files, or 5 where the 5th is 0 bytes'
tput bold; tput setaf 4; echo -n '#5 POINTS:'; tput sgr0; echo ' Should be only one error about plaintext5 being bad'
((tot += 25))
rm -f ciphertext*
rm -f plaintext*_*

echo 'Ten second sleep, your program must complete in this time'
timeout 10 sh 3>empty 2>notempty << __CMDS__
limit() {
  suffix=\$1
  shift
  rm -f STDOUT\$suffix
  rm -f STDERR\$suffix
  mkfifo STDOUT\$suffix
  mkfifo STDERR\$suffix
  head -c100000 < STDOUT\$suffix >&1 &
  head -c500 < STDERR\$suffix >&2 &
  "\$@" 1>STDOUT\$suffix 2>STDERR\$suffix
}
limit 1 cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin enc_client -- plaintext1 key70000 $encport > ciphertext1 2>&3 &
limit 2 cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin enc_client -- plaintext2 key70000 $encport > ciphertext2 2>&3 &
limit 3 cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin enc_client -- plaintext3 key70000 $encport > ciphertext3 2>&3 &
limit 4 cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin enc_client -- plaintext4 key70000 $encport > ciphertext4 2>&3 &
limit 5 cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin enc_client -- plaintext5 key70000 $encport > ciphertext5 &
wait
__CMDS__
ret=$?
cat empty notempty

# New loop for comparing file sizes
# wc -c ciphertext{1..4} | awk '{print $1}' > ciphertext_sizes.txt
# wc -c plaintext{1..4} | awk '{print $1}' > plaintext_sizes.txt
# cat ciphertext_sizes.txt plaintext_sizes.txt
# echo "diffing"
# diff ciphertext_sizes.txt plaintext_sizes.txt > diff.txt
# cat diff.txt
# echo "cmping"
# echo cmp  <(wc -c ciphertext{1..4} | awk '{print $1}') <(wc -c plaintext{1..4} | awk '{print $1}')
# echo "md5"
# md5sum ciphertext{1..4} > ciphertext_md5sums.txt
# md5sum plaintext{1..4} > plaintext_md5sums.txt
# diff ciphertext_md5sums.txt plaintext_md5sums.txt > diff_md5sums.txt
# cat diff_md5sums.txt
all_files_match=true
for i in {1..4}; do
    ciphertext_size=$(wc -c "ciphertext$i" | awk '{print $1}')
    echo "ciphertext size: $ciphertext_size"
    plaintext_size=$(wc -c "plaintext$i" | awk '{print $1}')
    echo "plaintext size: $plaintext_size"
    if [ "$ciphertext_size" -ne "$plaintext_size" ]; then
        echo "Mismatch in file sizes for pair $i: ciphertext$i ($ciphertext_size) vs plaintext$i ($plaintext_size)"
        all_files_match=false
        break
    fi
done
# end of new loop
if [ $ret -eq 124 ]
then
        tput bold
        tput setaf 1
        echo "Timed out within 10 seconds"
  ls -la plaintext* ciphertext*
        tput sgr0
# elif cmp  <(wc -c ciphertext{1..4} | awk '{print $1}') <(wc -c plaintext{1..4} | awk '{print $1}')
elif $all_files_match
then
        tput bold
        tput setaf 2
        echo "Files sizes match!"
        tput sgr0
        ((pts += 20))
else
        tput bold
        tput setaf 1
        echo "File sizes don't match :("
  ls -la plaintext* ciphertext*
        tput sgr0
fi

if [ -s notempty ] && [ ! -s empty ]
then
        echo "Only one error!"
        ((pts+=5))
else
        echo "multiple errors"
fi

echo
echo '#-----------------------------------------'
tput bold; tput setaf 4; echo -n '#15 POINTS:'; tput sgr0; echo ' concurrent test of decryption - look for 4 plaintext#_a files that match the plaintext# files'
((tot+=15))
echo '#Ten second sleep, your program must complete in this time'
timeout 10 sh << __CMDS__
limit() {
  suffix=\$1
  shift
  rm -f STDOUT\$suffix
  rm -f STDERR\$suffix
  mkfifo STDOUT\$suffix
  mkfifo STDERR\$suffix
  head -c100000 < STDOUT\$suffix >&1 &
  head -c500 < STDERR\$suffix >&2 &
  "\$@" 1>STDOUT\$suffix 2>STDERR\$suffix
}
limit 1 cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin dec_client -- ciphertext1 key70000 $decport > plaintext1_a &
limit 2 cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin dec_client -- ciphertext2 key70000 $decport > plaintext2_a &
limit 3 cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin dec_client -- ciphertext3 key70000 $decport > plaintext3_a &
limit 4 cargo run --manifest-path="$PROJECT_PATH/Cargo.toml" --bin dec_client -- ciphertext4 key70000 $decport > plaintext4_a &
wait
__CMDS__
ret=$?
if [ $ret -eq 124 ]
then
        tput bold
        tput setaf 1
        echo "Timed out within 10 seconds"
  ls -la plaintext* ciphertext*
        tput sgr0
elif cmp plaintext1{,_a} && cmp plaintext2{,_a} && cmp plaintext3{,_a} && cmp plaintext4{,_a}
then
        tput bold
        tput setaf 2
        echo "Files match!"
        tput sgr0
        ((pts+=15))
else
        tput bold
        tput setaf 1
        echo "Files don't match :("
  ls -la plaintext* ciphertext*
        tput sgr0
fi