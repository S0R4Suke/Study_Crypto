#include <iostream>
#include "seal/seal.h"
#include "example.h"
#include <iostream>
#include <fstream>
#include <vector>

using namespace std;
using namespace seal;

int main()
{
	//コンテナのパラメータ parms を設定
	EncryptionParameters parms(scheme_type::ckks);
	
	/*CKKSパラメータ：
	1.poly_module_degree(多項式係数)
	2.coeff_modulus（パラメータ係数）
	3.scale（規模）
	*/
	size_t poly_modulus_degree = 8192;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

	//scale = 2^40
	double scale = pow(2.0, 40);
	
	////SEALcontext = パラメータを使用してCKKSフレームワークを生成する
	SEALContext context(parms);

	//各モジュールをビルドする
	//最初にkeygeneratorを構築し、公開鍵、秘密鍵、および再線形化鍵を生成します
	KeyGenerator keygen(context);
	auto secret_key = keygen.secret_key();

	PublicKey public_key;
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);




	//エンコーダー、暗号化モジュール、オペレーター、デコードモジュールを構築
	//暗号化には公開鍵pkが必要であり、復号化には秘密鍵skが必要であり、エンコーダーにはscaleが必要であることに注意
	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);

	CKKSEncoder encoder(context);

	vector<double> x, y, z;
		x = { 1.0, 2.0, 3.0 };
		y = { 2.0, 3.0, 4.0 };
		z = { 3.0, 4.0, 5.0 };

	//ベクトルx、y、zをエンコードします
	Plaintext xp, yp, zp;
	encoder.encode(x, scale, xp);
	encoder.encode(y, scale, yp);
	encoder.encode(z, scale, zp);

	//プレーンテキストのxp、yp、zpを暗号化します
	Ciphertext xc, yc, zc;
	encryptor.encrypt(xp, xc);
	encryptor.encrypt(yp, yc);
	encryptor.encrypt(zp, zc);

	/*
	暗号文を計算するために説明する原則は次のとおりです。
	1.加算は連続して実行できますが、乗算は連続して実行できません
	2.暗号文乗算後の操作を再線形化します
	3.乗算を実行した後、再スケーリング操作を実行します
	4.操作の暗号文は、同じ回数（同じレベルで）再スケーリングを実行している必要があります
	上記の原則に基づいて計算する
	*/
	//中間変数
	Ciphertext temp;
	Ciphertext result_c;

	//x * yを計算し、暗号文を乗算し、再線形化および再スケーリング操作を実行します
	evaluator.multiply(xc,yc,temp);
	evaluator.relinearize_inplace(temp, relin_keys);
	evaluator.rescale_to_next_inplace(temp);

	// x * y * zを計算する前に、zは再スケーリング操作を実行していないため、zに対して乗算と再スケーリング操作を実行する必要があります。目的は、x*yとzを同じレベルにすることです。
	Plaintext wt;
	encoder.encode(1.0, scale, wt);

	//乗算および再スケーリング操作を実行します：
	evaluator.multiply_plain_inplace(zc, wt);
	evaluator.rescale_to_next_inplace(zc);

	//最後にtemp（x * y）* zc（z * 1.0）を実行します
	evaluator.multiply_inplace(temp, zc);
	evaluator.relinearize_inplace(temp,relin_keys);
	evaluator.rescale_to_next(temp, result_c);


	//復号化してデコード
	Plaintext result_p;
	decryptor.decrypt(result_c, result_p);

	//ベクトルにデコードすることに注意してください
	vector<double> result;
	encoder.decode(result_p, result);

	cout << "Result：" << endl;
	print_vector(result,3,3);
	return 0;
}