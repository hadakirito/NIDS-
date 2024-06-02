from setuptools import setup, find_packages

setup(
    name='nids',
    version='1.0',
    packages=find_packages(),
    install_requires=[
        'PyQt5',
        'psutil',
        'scapy',
    ],
    entry_points={
        'console_scripts': [
            'nids=nids:main',  # Ensure `main` is the correct entry point
        ],
    },
    author="Your Name",
    author_email="your.email@example.com",
    description="Network Intrusion Detection System (NIDS)",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url="https://github.com/yourusername/nids",  # Replace with your GitHub repository URL
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
    ],
    include_package_data=True,
    package_data={
        '': ['*.txt', '*.md'],
    },
    python_requires='>=3.6',
)
