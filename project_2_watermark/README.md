# 数字水印算法实现与应用（DCT域）

## 一、项目概述  
本项目实现**基于离散余弦变换（DCT）的数字水印算法**，支持水印嵌入、提取及鲁棒性测试。通过修改图像频域的**中频系数**嵌入水印，平衡“不可见性”与“鲁棒性”，适用于图像版权保护、内容认证等场景。  

### 核心特性：  
- 完整流程：覆盖“水印嵌入→提取”全链路，支持**非盲提取**（需原始图像辅助）。  
- 鲁棒性测试：内置8种攻击（噪声、压缩、几何变换等），输出**PSNR（图像质量）**和**BER（水印错误率）**量化指标。  


## 二、算法原理与数学计算  

### 1. 离散余弦变换（DCT）  
将图像从**空间域**转换到**频率域**，能量集中在低频，适合水印嵌入。对8×8图像块 \( B(i,j) \)（\( i,j \in [0,7] \)），二维DCT公式：  

$$  
D(u,v) = \alpha(u)\alpha(v) \sum_{i=0}^{7}\sum_{j=0}^{7} B(i,j) \cos\left(\frac{(2i+1)u\pi}{16}\right) \cos\left(\frac{(2j+1)v\pi}{16}\right)  
$$  

- \( \alpha(k) \)：归一化系数，\( \alpha(0)=\frac{1}{\sqrt{2}} \)，\( \alpha(k)=1 \)（\( k \geq 1 \)）。  
- **逆DCT（IDCT）**：从频率域恢复空间域图像，公式类似（略）。  


### 2. 水印嵌入公式  
选择**中频系数**（如 \( (2,2) \) 位置，平衡不可见性与鲁棒性），通过**量化调制**嵌入二进制水印：  

$$  
D'(u,v) = D(u,v) + \alpha \cdot q \cdot (w - 0.5)  
$$  

- \( D(u,v) \)：原始DCT系数；\( D'(u,v) \)：嵌入水印后的系数。  
- \( w \in \{0,1\} \)：水印比特；\( \alpha \)（嵌入强度，默认0.1）、\( q \)（量化步长，默认10）。  


### 3. 水印提取公式  
对比**原始图像**与**含水印图像**的DCT系数差异，恢复水印：  

$$  
w' = \begin{cases} 
1 & \text{若 } D'(u,v) - D(u,v) \geq 0 \\
0 & \text{否则}
\end{cases}  
$$  


### 4. 评估指标  
- **PSNR（峰值信噪比）**：衡量图像质量，值越高越好：  
  $$  
  \text{PSNR} = 10 \cdot \log_{10}\left( \frac{255^2}{\text{MSE}} \right), \quad \text{MSE} = \frac{1}{H \times W} \sum_{i,j} (I(i,j) - K(i,j))^2  
  $$  
  （\( I \)：原始图像，\( K \)：含水印图像，\( H,W \)：图像尺寸。）  

- **BER（比特错误率）**：衡量水印准确性，值越低越好：  
  $$  
  \text{BER} = \frac{\text{错误比特数}}{\text{总比特数}}  
  $$  


## 三、项目结构与文件说明  

### 1. 目录结构  
```  
project_2_watermark/  
├── README.md               # 项目文档（本文档）  
├── main.py                 # 主程序（串联流程）  
├── src/                    # 核心算法  
│   ├── __init__.py         # 包标识（空文件）  
│   ├── watermark.py        # DCT水印核心（嵌入、提取）  
│   ├── attacks.py          # 图像攻击函数（噪声、压缩等）  
│   ├── dct_transform.py    # DCT/IDCT变换  
│   └── utils.py            # 辅助工具（图像读写、指标计算）  
└── examples/               # 示例与输出  
    ├── lena.png            # 载体图像（无则自动生成测试图）  
    └── output/             # 结果目录  
        ├── original/       # 原始图像备份  
        ├── watermarked/    # 含水印图像  
        └── attacked/       # 攻击后图像  
```  


### 2. 文件功能  
| 文件路径                | 功能说明                                                                 |  
|-------------------------|--------------------------------------------------------------------------|  
| `main.py`               | 主流程：加载图像→嵌入水印→提取→鲁棒性测试→输出结果。                     |  
| `src/watermark.py`      | `DCTWatermark` 类：实现水印嵌入（`embed`）、提取（`extract`）、盲提取（`blind_extract`）。 |  
| `src/attacks.py`        | 图像攻击函数（如 `jpeg_compression`、`add_gaussian_noise` 等）。         |  
| `src/dct_transform.py`  | 二维DCT/IDCT变换实现（基于 `scipy`）。                                   |  
| `src/utils.py`          | 辅助工具：图像读写、文本-二进制转换、PSNR/BER计算、图像归一化。           |  


## 四、具体实现步骤  

### 1. 水印嵌入（`DCTWatermark.embed`）  
```python  
# 核心逻辑伪代码  
def embed(carrier_image, watermark_text):  
    # 1. 预处理：彩色图转灰度（保留通道信息用于输出）  
    gray_image = 转灰度(carrier_image)  

    # 2. 文本转二进制（如 "版权" → "01100001..."）  
    watermark_bits = text_to_binary(watermark_text)  

    # 3. 分块处理（8×8块）  
    for i in 0到高度步长8:  
        for j in 0到宽度步长8:  
            # 取完整8×8块（跳过边界不完整块）  
            block = gray_image[i:i+8, j:j+8]  
            dct_block = dct_2d(block)  # DCT变换（公式1）  

            # 嵌入水印：修改中频系数（如(2,2)位置）  
            if 还有未嵌入的比特:  
                bit = watermark_bits[当前索引]  
                u, v = (2, 2)  # 中频系数位置  
                dct_block[u, v] += α * q * (bit - 0.5)  # 公式2  
                当前索引 += 1  

            # 逆DCT变换，更新图像块  
            idct_block = idct_2d(dct_block)  
            gray_image[i:i+8, j:j+8] = idct_block  

    # 4. 输出：归一化+恢复通道（彩色图转3通道灰度）  
    normalized = normalize_image(gray_image)  
    if 原始图像是彩色:  
        return 三通道复制(normalized)  # 如 [g,g,g]  
    else:  
        return normalized  
```  


### 2. 水印提取（`DCTWatermark.extract`）  
```python  
# 核心逻辑伪代码  
def extract(original_image, watermarked_image, watermark_length):  
    # 1. 预处理：转灰度  
    orig_gray = 转灰度(original_image)  
    watermarked_gray = 转灰度(watermarked_image)  

    # 2. 分块处理（8×8块）  
    total_bits = watermark_length * 8  # 每个字符8位  
    extracted_bits = []  

    for i in 0到高度步长8:  
        for j in 0到宽度步长8:  
            # 取完整8×8块  
            orig_block = orig_gray[i:i+8, j:j+8]  
            watermarked_block = watermarked_gray[i:i+8, j:j+8]  

            # DCT变换  
            orig_dct = dct_2d(orig_block)  
            watermarked_dct = dct_2d(watermarked_block)  

            # 提取比特：对比系数差异（公式3）  
            if len(extracted_bits) < total_bits:  
                u, v = (2, 2)  
                diff = watermarked_dct[u, v] - orig_dct[u, v]  
                bit = '1' if diff >= 0 else '0'  
                extracted_bits.append(bit)  

            # 提前终止：已提取足够比特  
            if len(extracted_bits) >= total_bits:  
                break  
        if len(extracted_bits) >= total_bits:  
            break  

    # 3. 二进制转文本  
    return binary_to_text(''.join(extracted_bits))  
```  


### 3. 鲁棒性测试（`main.py`）  
```python  
# 核心逻辑伪代码  
def robustness_test(watermarked_image, watermark_text):  
    # 1. 定义攻击列表（噪声、压缩、几何变换等）  
    attacks = [  
        ("高斯噪声", lambda x: add_gaussian_noise(x, var=0.001)),  
        ("JPEG压缩", lambda x: jpeg_compression(x, quality=50)),  
        ("裁剪", lambda x: crop_image(x, ratio=0.1)),  
        # ... 其他攻击  
    ]  

    # 2. 遍历攻击，记录结果  
    results = []  
    original_bits = text_to_binary(watermark_text)  

    for name, attack_func in attacks:  
        # 应用攻击  
        attacked_img = attack_func(watermarked_image.copy())  

        # 提取水印+计算BER  
        extracted_text = watermarker.extract(original_image, attacked_img, len(watermark_text))  
        extracted_bits = text_to_binary(extracted_text)  
        ber_val = ber(original_bits, extracted_bits)  

        # 保存结果  
        results.append( (name, ber_val, extracted_text[:30]) )  

    # 3. 输出攻击后图像+BER表格  
    保存攻击图像(attacked_img, 路径)  
    打印结果表格(results)  
```  





## 六、测试结果分析（示例）  

| 攻击类型       | 比特错误率（BER） | 结果解读                     |  
|----------------|------------------|------------------------------|  
| 原始图像       | 0.0000           | 无攻击时提取完全准确         |  
| 高斯噪声攻击   | 0.0000           | 对高斯噪声鲁棒性强           |  
| 椒盐噪声攻击   | 0.0000           | 对椒盐噪声鲁棒性强           |  
| JPEG压缩攻击   | 0.0000           | 对压缩失真抵抗能力强         |  
| 裁剪攻击       | 0.5409           | 对裁剪敏感（几何变换影响大） |  
| 旋转攻击       | 0.5096           | 对旋转敏感（几何变换影响大） |  
| 高斯模糊攻击   | 0.0048           | 对模糊鲁棒性较强             |  
| 缩放攻击       | 0.0000           | 对缩放变换鲁棒性强           |  


**结论**：算法对**噪声、压缩、模糊**等“非几何攻击”表现优异，但对**裁剪、旋转**等“几何攻击”抵抗较弱（BER接近0.5，接近随机），需后续优化。  

