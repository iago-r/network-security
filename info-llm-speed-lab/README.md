# Running Llama 3 over a cluster of machines at SPEED Lab

As of now, it is possible to run a few versions of Llama 3 locally at SPEED Lab.

The machine hosting the model exposes a port that can be interacted with using the OpenAI API from any other machine in the lab.

We use the cluster of machines known internally as gorgonas to run the models since they are equipped with an RTX 4090 (1-4) or an RTX 3090 Ti (5-7, 10).

Currently, gorgonas1-7 and 10 are available. gorgona8 is not officially part of the cluster and is not supported, as for gorgona9, it does not exist.

## Setup overview

We use [llama-cpp](https://github.com/ggerganov/llama.cpp) as a framework to run the models. Once set up, the framework consists of:

- One **host machine**. Has the model downloaded and exposes a port for interaction using the OpenAI API.
- Zero or more **RPC machines**. Exposes a port for interaction with the **host machine**, thus allowing for distributed inference. Does not need the model file.
- One **client machine**, can be any of the above or a different one. Interacts with the **host machine** using the OpenAI API, sends prompts to be evaluated, can send multiple prompts sequentially.

## Setting up

### Build tools

llama-cpp needs to be compiled from scratch to better suit the machine it will run, which includes support for CUDA and RPC.

We use Anaconda for consistency and to eliminate any possible differences between build environments.

To get started, connect to a gorgona of your choice and load the conda module by running:

```bash
module load anaconda3.2023.09-0
```

Check if conda is available by running:

```bash
conda --version
```

If set up correctly, this should print:

```txt
conda 23.7.4
```

Create and activate a conda environment:

```bash
conda create --prefix ~/choose/a/path
conda activate ~/choose/a/path
```

*NOTE: You can deactivate a conda environment by running `conda deactivate`, but you will need to activate the environment every time you want to run the model, since all build dependencies and shared libraries are part of the environment.*

For compilation, we need gcc, g++ and nvcc (Nvidia CUDA compiler), as well as the CUDA shared libraries. Thankfully, we can install all of this using conda.

Check available versions:

```bash
conda search cuda-toolkit
```

Sample output:

```txt
Loading channels: done
# Name                       Version           Build  Channel
cuda-toolkit                  12.0.0      h7428d3b_0  conda-forge

...

cuda-toolkit                  12.6.3      ha804496_0  conda-forge
```

Install any version above 12.0.

*For reference, we have tested the following steps with version 12.0*.

```bash
conda install cuda-toolkit=12.0
```

More details about using Anaconda to manage dependencies are available here: [SPEED docs - Managing dependencies](https://github.com/WillianJunior/SpeedUFMG/blob/main/user/gerencia-de-deps.md).

### Compiling llama-cpp

*After setting up the conda environment as described above*, head over to [llama-cpp on GitHub](https://github.com/ggerganov/llama.cpp/tree/master) and clone the repository.

After cloning, **cd into llama-cpp** (or wherever you have cloned the repo) and execute the following commands one at a time:

```bash
mkdir build-rpc-cuda
cd build-rpc-cuda
cmake .. -DGGML_CUDA=ON -DGGML_RPC=ON
cmake --build . --config Release
```

*NOTE: These compilation instructions were taken directly from the [llama-cpp docs](https://github.com/ggerganov/llama.cpp/tree/master/examples/rpc) and are subject to change.*

After the first cmake, check if the CUDA environment is being recognized and if CUDA and RPC support are included in the build:

```txt
-- Found CUDAToolkit: /path/to/targets/x86_64-linux/include (found version "12.0.76")
-- CUDA Toolkit found

...

-- Including CUDA backend
-- Using RPC backend
-- Including RPC backend
-- Configuring done
-- Generating done
-- Build files have been written to: /path/to/llama-cpp/build-rpc-cuda
```

The second cmake will compile llama-cpp, this process will take a while, close to an hour, so watch an episode of your favorite show while you wait.

Check if CUDA source files build successfully:

```txt
[  8%] Building CUDA object ggml/src/ggml-cuda/CMakeFiles/ggml-cuda.dir/acc.cu.o
[  9%] Building CUDA object ggml/src/ggml-cuda/CMakeFiles/ggml-cuda.dir/arange.cu.o
[  9%] Building CUDA object ggml/src/ggml-cuda/CMakeFiles/ggml-cuda.dir/argmax.cu.o
[ 10%] Building CUDA object ggml/src/ggml-cuda/CMakeFiles/ggml-cuda.dir/argsort.cu.o
```

After compilation, all binaries will be inside the **llama-cpp/build-rpc-cuda/bin** folder.

Repeat this compilation process for every gorgona machine you wish to use.

## Downloading a suitable model file

The model files for llama-cpp are .gguf files (GPT-Generated Unified Format), this is a file format for storing and using large language models.

You can download these models from [Hugging Face](https://huggingface.co/). We have tested quantized models, which are compressed versions suitable for low VRAM systems.

You can get the same models we have tested by following these instructions: [Downloading Llama 3](https://huggingface.co/bartowski/Reflection-Llama-3.1-70B-GGUF). We recommend using *huggingface-cli*.

Specifically, we have used:

- Reflection-Llama-3.1-70B-Q4_K_S (40 GB, needs 2 machines)
- Reflection-Llama-3.1-70B-Q6_K_L (59 GB, needs 3 machines)

Feel free to use other Hugging Face repos, *just be mindful to use .gguf models.*

The model size directly determines how many machines you need, since all GPUs installed have 24 GB of VRAM (of which 2 GB are used by the CUDA kernel), this means *22 GB is available per machine*:

- **40 GB:** 2 machines -> 1 host, 1 RPC server
- **59 GB:** 3 machines -> 1 host, 2 RPC servers

The model should be downloaded to just one machine, this machine will be the **host** as described in the initial section.

## Running the model

After setting up llama-cpp for every machine you wish to use and downloading a suitable .gguf file. Three steps remain to run Llama 3.

Go to the llama-cpp binaries folder: **llama-cpp/build-rpc-cuda/bin**.

Every command below is run from this folder.

### 1. Running RPC servers (RPC machines)

Firstly, set up the necessary amount of RPC servers, ensuring enough VRAM to fit the model as described in the previous section.

Run the following command:

```bash
./rpc-server -H <rpc_ip> -p <port>
```

Choose a free port of your liking and **choose an IP according to the gorgona you are using as RPC server**.

A list of gorgona IPs is present in the [Appendix](#appendix) at the end of this file.

This is necessary since all gorgonas run under a VLAN.

For gorgona5, the command will be:

```bash
./rpc-server -H 192.168.62.35 -p 50052
```

Check if the GPU is recongnized and if the server started successfully:

```txt
create_backend: using CUDA backend
ggml_cuda_init: GGML_CUDA_FORCE_MMQ:    no
ggml_cuda_init: GGML_CUDA_FORCE_CUBLAS: no
ggml_cuda_init: found 1 CUDA devices:
  Device 0: NVIDIA GeForce RTX 3090 Ti, compute capability 8.6, VMM: yes
Starting RPC server on 192.168.62.35:50052, backend memory: 23972 MB
```

*NOTE: If the line "Starting RPC server ..." does not show, then the server hasn't started. Check if the port you chose is available and wait. In some rare cases, the server takes a few minutes to start. If the server doesn't start, end the process and try again.*

Repeat this process for as many RPC servers as you need, leave them running and proceed to the next step.

### 2. Running host server (host machine)

On the host machine, which has the .gguf file, run:

```bash
./llama-server -m /path/to/model.gguf -c 8192 -ngl 99 --rpc <rpc_ip1>:<port>,<rpc_ip2>:<port> --host <server_ip> --port <server_port>
```

Where:

- `model.gguf` is a model file respecting the instructions above.

- `rpc_ip` and `port` is the IP and port of a running RPC server. Note that each `rpc_ip:port` pair is separated using a comma.

- `server_port` is a free port of your choosing and `server_ip` is an **IP according to the gorgona you are using as a host**. This is the IP the client will connect to in order to send prompts.

- `-ngl` indicates how many layers of the model should run in the GPUs, increase this number if the model is spilling onto the CPU.

- `-c` indicates the context window size, increase this if you want more context. Note that bigger contexts require more VRAM, as such, you may need more RPC servers for extremely big contexts.

You can run `llama-server` with a `-h` flag to see the full list of options.

For gorgona1 as the host and gorgona5 as an RPC server, the command will be:

```bash
./llama-server -m ~/.cache/gguf/Reflection-Llama-3.1-70B-Q4_K_S.gguf -c 8192 -ngl 99 --rpc 192.168.62.35:50052 --host 192.168.62.31 --port 50001
```

Check if the GPU is recognized and the RPC servers are working:

```txt
ggml_cuda_init: found 1 CUDA devices:
  Device 0: NVIDIA GeForce RTX 4090, compute capability 8.9, VMM: yes 

...

llm_load_tensors: RPC[192.168.62.35:50052] buffer size = 19142.56 MiB
llm_load_tensors:        CPU buffer size =   563.65 MiB
llm_load_tensors:      CUDA0 buffer size = 18764.46 MiB

...

main: server is listening on 192.168.62.31:50001 - starting the main loop
```

*NOTE: If an RPC server does not show in the log, as shown above, check your IP settings. Also note that failing to connect to an RPC server may lead to an assertion error. This happens if no RPC server is detected, llama-server will try to allocate memory in only one GPU and the model may not fit.*

To run .gguf models with multiple files, use just the first file as an argument, llama-server will load the rest:

```bash
./llama-server -m ~/.cache/gguf/Reflection-Llama-3.1-70B-Q6_K_L/Reflection-Llama-3.1-70B-Q6_K_L-00001-of-00002.gguf
```

Leave the server running (and all associated RPC servers) and proceed to the next step.

### 3. Running client (client machine)

Lastly, from Python you can connect to the **host machine** and send prompts.

Install dependencies

```bash
pip install openai
```

Sample Python code:

```python
import openai

system_prompt = "your sys prompt"
system_prompt = "your user prompt"

llm = openai.OpenAI(
    base_url="http://<server_ip>:<server_port>/v1",
    api_key = "sk-no-key-required"
)


out = llm.chat.completions.create(
    model="llama-3-70b-q6",
    messages = [
        {
            "role": "system",
            "content": f"{system_prompt}"
        },
        {
            "role": "user",
            "content": f"{user_prompt}"
        }
    ],
    max_tokens=None,

print(out)
)

```

Where `server_ip` and `server_port` are the **host machine** IP and port as described above.

## Appendix

List of gorgonas IPs

- gorgona1  : 192.168.62.31
- gorgona2  : 192.168.62.32
- gorgona3  : 192.168.62.33
- gorgona4  : 192.168.62.34
- gorgona5  : 192.168.62.35
- gorgona6  : 192.168.62.36
- gorgona7  : 192.168.62.37
- gorgona9  : 192.168.62.39
- gorgona10 : 192.168.62.40
