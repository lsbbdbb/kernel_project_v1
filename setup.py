from setuptools import setup, find_packages

setup(
    name="kernel-livepatch-agent",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "pyyaml>=5.0",
        "openai>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "run=agent.__main__:main",
        ],
    },
    python_requires=">=3.6",
)
