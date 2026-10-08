#!/usr/bin/env bash
# Run any project script on the NVIDIA GPU through WSL2 (Ubuntu-22.04).
#
#   wsl -d Ubuntu-22.04 -- /mnt/d/base_imp/aad/scripts/gpu.sh scripts/02_train_baselines.py --models mlp
#   wsl -d Ubuntu-22.04 -- /mnt/d/base_imp/aad/scripts/gpu.sh -m pytest tests -q
#
# TF 2.13.1 on Linux needs CUDA 11.8 + cuDNN 8.6. They come from NVIDIA's pip wheels
# inside ~/aad-venv (no system CUDA install), so the loader path is set here.
set -euo pipefail

VENV="${AAD_VENV:-$HOME/aad-venv}"
NV="$("$VENV/bin/python" -c 'import nvidia, os; print(os.path.dirname(nvidia.__file__))')"

LIBS=":/usr/lib/wsl/lib"                                      # libcuda.so from the Windows driver
for d in "$NV"/*/lib; do LIBS="$LIBS:$d"; done
export LD_LIBRARY_PATH="${LIBS#:}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PATH="$NV/cuda_nvcc/bin:$PATH"                         # ptxas for XLA
export XLA_FLAGS="--xla_gpu_cuda_data_dir=$NV/cuda_nvcc"
export TF_FORCE_GPU_ALLOW_GROWTH=true                         # 4 GB card: allocate on demand
export TF_CPP_MIN_LOG_LEVEL="${TF_CPP_MIN_LOG_LEVEL:-1}"

cd "$(dirname "$0")/.."
exec "$VENV/bin/python" "$@"
