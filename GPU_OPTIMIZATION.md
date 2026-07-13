# GPU & Performance Optimization Roadmap

## Current State
The TSCM suite runs all DSP on CPU using scipy/numpy. On a machine with a modern GPU (NVIDIA RTX 40-series, AMD Radeon 7000-series, or Intel Arc), we're using <5% of available compute.

## Immediate Wins

### 1. cuFFT / GPU FFT (10-50x speedup)
Replace `scipy.fft` with GPU-accelerated FFT:
```python
# Before (CPU)
spectrum = np.fft.fft(iq_samples, n=fft_size)

# After (GPU with CuPy)
import cupy as cp
iq_gpu = cp.array(iq_samples)
spectrum = cp.fft.fft(iq_gpu, n=fft_size)
spectrum_cpu = cp.asnumpy(spectrum)
```
- Works with CuPy (NVIDIA) or PyTorch (all GPUs)
- 20MHz FFT at 2.4MSps = massive parallelism
- Enables real-time waterfall spectrogram at full bandwidth

### 2. GPU Neural Network Inference (100x speedup)
The `NeuralDetector` is trained but never runs inference. Fix:
```python
# Load model to GPU
model = torch.load('models/rf_classifier.pt')
model = model.cuda()  # or .to('mps') for Mac

# Inference on GPU - batch all FFT bins
spectrogram = torch.tensor(spec_batch).cuda()
predictions = model(spectrogram)
```
- PyTorch works on NVIDIA, AMD (ROCm), Intel (oneAPI), Apple (MPS)
- Can process entire 20MHz bandwidth in one pass

### 3. Multi-threaded Detector Pipeline
Current architecture: sequential single-thread detection loop.
Refactor to pipeline:
```
[IQ Capture] -> [FFT Thread] -> [Detector Pool] -> [Source Engine] -> [Map Server]
     |              |                  |                   |                  |
   HackRF       cuFFT            8 workers          Kalman filter      WebSocket
   BladeRF      Spectrogram     PyTorch CNN        Bearing fusion     Leaflet
   RTL-SDR       Waterfall       PLL/Costas         Persistence        REST API
```

### 4. Memory-Mapped IQ Buffer
Instead of copying IQ data between threads, use shared memory:
```python
from multiprocessing import shared_memory
shm = shared_memory.SharedMemory(create=True, size=buffer_size)
# All threads read/write same buffer - zero-copy
```

## Hardware-Specific Optimization

### NVIDIA (CUDA)
- cuFFT for FFT, cuBLAS for linear algebra
- TensorRT for neural network inference
- NVML for GPU monitoring (thermal, power)
- **Install:** `pip install cupy-cuda12x`

### AMD (ROCm)
- rocFFT, rocBLAS
- PyTorch with ROCm backend
- **Install:** PyTorch ROCm wheels from pytorch.org

### Intel (oneAPI / OpenVINO)
- Intel oneAPI Math Kernel Library
- OpenVINO for neural network inference
- Works on Intel Arc and integrated GPUs
- **Install:** `pip install openvino`

### Apple Silicon (MPS)
- PyTorch MPS backend (built-in)
- Metal Performance Shaders
- **Install:** `pip install torch` (MPS auto-detected)

### No Dedicated GPU (Integrated)
- Vulkan compute shaders via PyVulkan
- OpenCL via pyopencl
- SIMD optimization with numba
- **Install:** `pip install numba pyopencl`

## Performance Targets
| Operation | Current (CPU) | Target (GPU) | Speedup |
|-----------|---------------|-------------|---------|
| 20MHz FFT | 45ms | 0.5ms | 90x |
| Spectrogram | 200ms | 5ms | 40x |
| NN Inference | (not running) | 1ms | N/A |
| AoA Phase | 2ms | 0.1ms | 20x |
| Full Pipeline | ~3s/cycle | ~50ms/cycle | 60x |

## How to Help
See [HELP_WANTED.md](HELP_WANTED.md) — GPU optimization is our #1 priority.
