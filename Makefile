# Reflector Assignment

run:
	echo "#!/bin/bash" > reflector
	echo 'python3 reflector.py $$@' >> reflector
	chmod +x reflector
