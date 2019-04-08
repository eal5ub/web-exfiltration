TARGET=main
RUNFLAGS=-policy=1

.PHONY: experiment
experiment: $(TARGET) codesign
	./$(TARGET) -policy=3 -open-url="https://ethanlowman.com/" --upload-results

.PHONY: p0
p0: $(TARGET) codesign
	./$(TARGET) -policy=0

.PHONY: p1
p1: $(TARGET) codesign
	./$(TARGET) -policy=1

.PHONY: p2
p2: $(TARGET) codesign
	./$(TARGET) -policy=2

.PHONY: p3
p3: $(TARGET) codesign
	./$(TARGET) -policy=3

.PHONY: run
run: $(TARGET) codesign
	./$(TARGET) $(RUNFLAGS)

.PHONY: headless
headless: $(TARGET) codesign
	./$(TARGET) $(RUNFLAGS) -headless

.PHONY: verbose
verbose: $(TARGET) codesign
	./$(TARGET) $(RUNFLAGS) -verbose -chromium-log

.PHONY: dependencies
dependencies:
	go get ./...

.PHONY: $(TARGET)
$(TARGET):
	go build -o $(TARGET)

.PHONY: codesign
codesign:
	codesign -fs "Ethan Lowman Signing Identity" ./$(TARGET)
	rm -f $(TARGET).cstemp

.PHONY: clean
clean:
	rm -f main

cert/cert.crt cert/key.pem: cert/openssl.cnf
	openssl req -x509 -newkey rsa:2048 -keyout cert/key.pem -out cert/cert.crt -days 3650 -subj "/CN=localhost" -config cert/openssl.cnf

