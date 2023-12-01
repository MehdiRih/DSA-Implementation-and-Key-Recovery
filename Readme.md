# Digital Signature Algorithm (DSA) Implementation and Key Recovery Demonstration

This repository contains a Python implementation of the Digital Signature Algorithm (DSA) along with a demonstration of how reusing the same nonce (`k`) in the signing process can lead to the compromise of the private key.

## Description

The project is split into two main files:

- `DSA.py`: Implements the core functionalities of DSA, including prime number generation, key pair generation, message signing, and signature verification.
- `Key_Recovery.py`: Demonstrates the use of the DSA implementation and includes a function to recover the private key if the same nonce (`k`) is reused across different signatures.

## Getting Started

### Dependencies

- Python 3.x
- `pycryptodome` package for cryptographic operations

### Installing

- Clone the repository to your local machine.
- Ensure you have Python 3.x installed.
- Install `pycryptodome` using pip:

```bash
pip install pycryptodome
```


### Executing the Program

- Run `DSA.py` to see the DSA operations in action.
- Run `Key_Rocovery.py` to see the demonstration of key recovery.

## Contributing

Contributions to this project are welcome. Please follow these steps:

1. Fork the repository.
2. Create a new branch: `git checkout -b your-branch-name`.
3. Make your changes and commit them: `git commit -m 'Commit message'`.
4. Push to the original branch: `git push origin your-branch-name`.
5. Create the pull request.

Alternatively, see the GitHub documentation on [creating a pull request](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request).

## Authors

Mehdi Rihani

## License

This project is licensed under the [MIT License](LICENSE.txt) - see the LICENSE file for details.
