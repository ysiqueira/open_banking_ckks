yes | rm -rf build/* 
cd build

cmake -Dhelib_DIR=/Users/yaissasiqueira/Desktop/repos/helib_tests/helib/HElib/build/helib_pack/share/cmake/helib /Users/yaissasiqueira/Desktop/repos/helib_tests/bank_app/bank_application .. 

make -j16