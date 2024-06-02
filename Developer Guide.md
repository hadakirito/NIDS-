# Developer Guide for Network Intrusion Detection System (NIDS)

## Project Structure

- **Nids.py**: Main script for running the NIDS application.
- **profile_script.py**: Script for profiling the PacketAnalyzer class.
- **setup.py**: Setup script for packaging the NIDS project.
- **test_packet_analyzer.py**: Unit tests for the PacketAnalyzer class.
- **test_gui.py**: Unit tests for the NIDS GUI.
- **test_integration.py**: Integration tests for the full workflow.
- **README.md**: User guide.
- **DEVELOPER.md**: Developer guide.

## Environment Setup

1. **Clone the repository**:
    ```bash
    git clone https://github.com/hadakirito/NIDS-.git
    cd nids
    ```

2. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Set environment variables**:
    ```bash
    export SMTP_USERNAME='your_username'
    export SMTP_PASSWORD='your_password'
    ```

## Running the Application

1. **Run the application**:
    ```bash
    python Nids.py
    ```

## Running Tests

1. **Run all tests**:
    ```bash
    python -m unittest discover
    ```

2. **Run specific test files**:
    ```bash
    python test_packet_analyzer.py
    python test_gui.py
    python test_integration.py
    ```

## Packaging

1. **Build the package**:
    ```bash
    python setup.py sdist bdist_wheel
    ```

2. **Create executable using PyInstaller**:
    ```bash
    pyinstaller --onefile Nids.py
    ```

## Profiling

1. **Run the profile script**:
    ```bash
    python profile_script.py
    ```

## Logging

- Logs are saved to `Logs.log`.
- Logging configuration can be found in `Nids.py`.

## Contributing

- Fork the repository.
- Create a new branch for your feature or bugfix.
- Open a pull request once your changes are tested.
