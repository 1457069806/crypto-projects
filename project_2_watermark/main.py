import os
import numpy as np
from src.watermark import DCTWatermark
from src.utils import (
    load_image, save_image, psnr, ber,
    text_to_binary, binary_to_text
)
from project_2_watermark.src.attacks import (
    add_gaussian_noise, add_salt_pepper_noise,
    jpeg_compression, crop_image, rotate_image,
    gaussian_blur, resize_image
)


def main():
    # 确保输出目录存在
    output_dirs = [
        "examples/output/original",
        "examples/output/watermarked",
        "examples/output/attacked"
    ]
    for dir in output_dirs:
        os.makedirs(dir, exist_ok=True)

    # 水印文本
    watermark_text = "Copyright 2023 Crypto-Projects. All rights reserved."
    print(f"水印文本: {watermark_text}")

    # 加载或创建载体图像
    carrier_path = "examples/lena.png"
    if not os.path.exists(carrier_path):
        print("未找到示例图像，创建测试图像...")
        # 创建一个512x512的测试图像（确保尺寸固定）
        carrier_image = np.zeros((512, 512, 3), dtype=np.uint8)
        # 添加简单图案避免全黑图像
        carrier_image[100:400, 100:400] = [255, 255, 255]  # 白色方块
        carrier_image[200:300, 200:300] = [0, 0, 255]  # 蓝色方块
        save_image(carrier_image, carrier_path)
    else:
        carrier_image = load_image(carrier_path)

    # 保存原始图像用于对比
    save_image(carrier_image, "examples/output/original/original.png")

    # 初始化水印处理器
    watermarker = DCTWatermark(alpha=0.1, block_size=8)

    # 嵌入水印
    print("正在嵌入水印...")
    watermarked_image = watermarker.embed(carrier_image, watermark_text)

    # 保存含水印图像（使用PNG格式避免压缩导致的尺寸变化）
    save_path = "examples/output/watermarked/watermarked.png"
    save_image(watermarked_image, save_path)

    # 计算并显示PSNR（评估图像质量）
    current_psnr = psnr(carrier_image, watermarked_image)
    print(f"嵌入水印后的PSNR值: {current_psnr:.2f} dB")
    print("(PSNR值越高，图像质量越好，通常大于30dB人眼难以察觉差异)")

    # 提取水印（直接使用内存中的图像对象，避免重新加载导致尺寸问题）
    print("正在提取水印...")
    # 先检查尺寸是否一致
    if carrier_image.shape != watermarked_image.shape:
        print(f"警告：图像尺寸不一致 - 原始: {carrier_image.shape}, 水印: {watermarked_image.shape}")
        # 尝试调整尺寸（仅作为兼容措施）
        from PIL import Image
        watermarked_image = np.array(Image.fromarray(watermarked_image).resize(
            (carrier_image.shape[1], carrier_image.shape[0]),
            Image.Resampling.LANCZOS
        ))

    extracted_text = watermarker.extract(carrier_image, watermarked_image, len(watermark_text))
    print(f"提取的水印: {extracted_text[:50]}...")  # 只显示前50个字符

    # 验证提取结果
    is_success = watermark_text == extracted_text
    print(f"水印提取{'成功' if is_success else '失败'}")

    # 鲁棒性测试
    print("\n开始鲁棒性测试...")
    attack_functions = [
        ("原始图像", lambda x: x),  # 无攻击作为基准
        ("高斯噪声攻击", lambda x: add_gaussian_noise(x, mean=0, var=0.001)),
        ("椒盐噪声攻击", lambda x: add_salt_pepper_noise(x, prob=0.01)),
        ("JPEG压缩攻击", lambda x: jpeg_compression(x, quality=50)),
        ("裁剪攻击", lambda x: crop_image(x, ratio=0.1)),
        ("旋转攻击", lambda x: rotate_image(x, angle=5)),
        ("高斯模糊攻击", lambda x: gaussian_blur(x, radius=3)),
        ("缩放攻击", lambda x: resize_image(x, scale=0.8))
    ]

    attack_results = []
    original_bits = text_to_binary(watermark_text)

    for name, attack_func in attack_functions:
        print(f"\n应用{name}...")
        # 应用攻击
        attacked_image = attack_func(watermarked_image.copy())

        # 保存受攻击的图像
        attack_save_path = f"examples/output/attacked/attacked_{name.replace(' ', '_')}.png"
        save_image(attacked_image, attack_save_path)

        # 从受攻击的图像中提取水印
        try:
            # 确保提取前尺寸一致
            if carrier_image.shape[:2] != attacked_image.shape[:2]:
                # 调整受攻击图像的尺寸以匹配原始图像
                from PIL import Image
                attacked_image = np.array(Image.fromarray(attacked_image).resize(
                    (carrier_image.shape[1], carrier_image.shape[0]),
                    Image.Resampling.LANCZOS
                ))

            extracted_attack_text = watermarker.extract(carrier_image, attacked_image, len(watermark_text))
            extracted_bits = text_to_binary(extracted_attack_text)

            # 计算比特错误率
            ber_val = ber(original_bits, extracted_bits)
            attack_results.append((name, ber_val, extracted_attack_text[:30]))

            print(f"{name}后提取的水印: {extracted_attack_text[:30]}...")
            print(f"{name}的比特错误率: {ber_val:.4f}")
        except Exception as e:
            print(f"{name}处理失败: {e}")
            attack_results.append((name, 1.0, "提取失败"))

    # 显示所有攻击的结果摘要
    print("\n鲁棒性测试结果摘要:")
    print("-" * 80)
    print(f"{'攻击类型':<30} {'比特错误率':<15} {'提取的水印片段'}")
    print("-" * 80)
    for name, ber_val, text in attack_results:
        print(f"{name:<30} {ber_val:.4f} {text}")
    print("-" * 80)


if __name__ == "__main__":
    main()
