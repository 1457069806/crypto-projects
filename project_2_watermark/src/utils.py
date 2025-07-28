import numpy as np
from PIL import Image
import os


def text_to_binary(text):
    """将文本转换为二进制字符串"""
    binary = ''.join(format(ord(char), '08b') for char in text)
    return binary


def binary_to_text(binary):
    """将二进制字符串转换为文本"""
    text = ''
    # 确保二进制长度是8的倍数
    binary = binary.ljust((len(binary) + 7) // 8 * 8, '0')
    for i in range(0, len(binary), 8):
        byte = binary[i:i + 8]
        if byte == '00000000':  # 遇到空字符停止
            break
        text += chr(int(byte, 2))
    return text


def normalize_image(image):
    """将图像像素值归一化到0-255范围"""
    img_min = np.min(image)
    img_max = np.max(image)
    if img_max - img_min == 0:
        return np.zeros_like(image, dtype=np.uint8)
    return ((image - img_min) / (img_max - img_min) * 255).astype(np.uint8)


def load_image(image_path):
    """加载图像并转换为numpy数组（保持原始尺寸）"""
    try:
        with Image.open(image_path) as img:
            # 转换为RGB模式（避免PNG等格式的通道问题）
            img = img.convert('RGB')
            return np.array(img)
    except Exception as e:
        print(f"加载图像失败: {e}")
        return None


def save_image(image, save_path):
    """保存图像（确保尺寸不变）"""
    try:
        # 创建保存目录
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        # 确保图像是uint8类型且在0-255范围内
        if image.dtype != np.uint8:
            image = normalize_image(image)

        # 保存图像，不改变尺寸
        img = Image.fromarray(image)
        # 保存为PNG格式以避免JPEG压缩导致的尺寸/质量变化
        img.save(save_path, format='PNG')
        print(f"图像已保存至: {save_path}")
    except Exception as e:
        print(f"保存图像失败: {e}")


def psnr(original, watermarked):
    """计算峰值信噪比（评估图像质量）"""
    # 确保图像尺寸一致
    if original.shape != watermarked.shape:
        raise ValueError("原始图像和含水印图像必须具有相同的尺寸")

    # 确保数据类型正确
    original = original.astype(np.float64)
    watermarked = watermarked.astype(np.float64)

    mse = np.mean((original - watermarked) ** 2)
    if mse == 0:
        return float('inf')  # 完全相同，PSNR无穷大
    max_pixel = 255.0
    return 20 * np.log10(max_pixel / np.sqrt(mse))


def ber(original_bits, extracted_bits):
    """计算比特错误率（评估水印提取准确性）"""
    if len(original_bits) != len(extracted_bits):
        # 取较短的长度进行比较
        min_len = min(len(original_bits), len(extracted_bits))
        original_bits = original_bits[:min_len]
        extracted_bits = extracted_bits[:min_len]

    errors = sum(b1 != b2 for b1, b2 in zip(original_bits, extracted_bits))
    return errors / len(original_bits) if len(original_bits) > 0 else 0.0
