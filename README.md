# Cryptographic Functions

This repository is an ongoing learning experience in understanding how to implement various cryptographic functions. Currently the following functions have been implemented:

* SHA-256

## Getting Started

These instructions will you get a copy of the project up and running on your local machine for deployment and testing purpose. Please checkout the [blogpost on SHA-256](https://craigllangford.com/sha-256/) for full details of how the cryptographic function works you can also test your implementation against it!

### Prerequisites

This app runs using Python 3.6.1. Please checkout [www.python.org](https://www.python.org) to install it on your own system. It is recommended to build the project in a contained virtual environment. This can be achieved with a combination of [Virtualenv](https://virtualenv.pypa.io/en/stable/) and the [Virtualenv Wrapper](https://virtualenvwrapper.readthedocs.io/en/latest/) which allows you to create and delete Virtualenvs easily. 

### Installing

The first step to installing the app is to clone the git repository:

```bash
$ git clone https://github.com/CraigLangford/Cryptographic-Functions.git
```

If you have virtualenv and virtualenvwrapper installed (See [Prerequisites](#prerequisites)), create your Python 3.6 environment.

```bash
$ mkvirtualenv --python=python3.6 cryptofunctions
```

You can set the root directory of the project as well so whenever you run `workon cryptoprice` you'll be in your virtualenv in your root folder immediately.

```bash
$ setvirtualenvproject
```

You should now be in the root directory with Python 3.6.x as your Python version.

```bash
$ ls
LICENSE  README.md  sha256
$ python --version
Python 3.6.1
```

That's it! You're now set up to work locally, these functions perform in pure Python. You can build some tests in the corresponding test_*.py file in each directory to test locally (see [Running the Tests](#running-the-tests))!

## Running the Tests

Python's Unittest is used for testing the application, and comes with python. If you already followed the steps in [Installing](#installing) you're good to go! Just run the following on the root directory of the project to run the tests for the project.

*Example testing in sha256/*
```bash
$ python test_sha256.py
```

## Deployment

The project is good to go after setting up your Python environment. Just run python3 /path/to/function.py and you'll be able to interact with the function.

*SHA-256 bash example*
```bash
$ python sha256.py
> Input string: abc
> SHA-256 digest: BA7816BF 8F01CFEA 414140DE 5DAE2223 B00361A3 96177A9C B410FF61 F20015AD
```

## Contributing

## Authors

* **Craig Langford** - *Initial Work* - https://github.com/CraigLangford

Please feel free to contribute to be added to the project!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

* The SHA-256 function was build based entirely off of the documents released by the NSA [here](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf) and [here](http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA256.pdf).
