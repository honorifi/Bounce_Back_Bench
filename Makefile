install	:
	g++ src/main.cpp -o bounce_back -lssl -lcrypto

prepare	:
	bash ./key_generator.sh