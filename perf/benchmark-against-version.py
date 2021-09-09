import logging
import argparse
import os
import subprocess
import sys
import venv
from pathlib import Path

logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(stream=sys.stderr)
handler.setFormatter(
    logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)
logger.addHandler(handler)

def get_benchmark_script_args(carrot_args):
    actual_args = []
    for arg in carrot_args:
        new_arg = arg.replace('^', '--')
        actual_args.append(new_arg)
    return actual_args

def parse_args():
    parser = argparse.ArgumentParser()
    # Add arguments here
    parser.add_argument(
        "--against",
        "-a",
        required=True,
        help="Semantic version string of semgrep version you wish to test against.")
    parser.add_argument(
        "--semgrep-core",
        "-s",
        help="Path to local semgrep-core build.")
    parser.add_argument(
        "--benchmark-args", "-b", nargs='+', default=[],
        help="Arguments you wish to pass to the benchmarking script run-benchmarks. \
              However, instead of using '--<arg>', use '^<arg>' so parser isn't confused.")

    return parser.parse_args()

def main():
    args = parse_args()

    builder = venv.EnvBuilder(
        clear=True,
        with_pip=True,
    )
    venv_path = Path(f"semgrep-{args.against}")
    builder.create(venv_path)

    # cf. https://docs.python.org/3/library/venv.html
    # When a virtual environment is active, the VIRTUAL_ENV environment variable is
    # set to the path of the virtual environment. This can be used to check if one
    # is running inside a virtual environment.
    #
    # You don’t specifically need to activate an environment; activation just prepends
    # the virtual environment’s binary directory to your path, so that “python” invokes
    # the virtual environment’s Python interpreter and you can run installed scripts
    # without having to use their full path. However, all scripts installed in a virtual
    # environment should be runnable without activating it, and run with the virtual
    # environment’s Python automatically.

    os.environ["VIRTUAL_ENV"] = str(venv_path.absolute())
    os.environ[
        "PATH"
    ] = f"{str(venv_path.absolute() / 'bin')}{os.pathsep}{os.environ['PATH']}"

    subprocess.run(["pip", "install", f"semgrep=={args.against}"])

    subprocess.run(
        [
            "which",
            "semgrep",
        ]
    )

    subprocess.run(["semgrep", "--version"])

    benchmarks_command = ["./run-benchmarks"] + get_benchmark_script_args(args.benchmark_args)
    logger.info(f"benchmarks command is {benchmarks_command}")
    subprocess.run(benchmarks_command)

if __name__ == "__main__":
    main()
