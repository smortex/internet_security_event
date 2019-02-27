# frozen_string_literal: true

RSpec.describe InternetSecurityEvent::TLSAStatus do
  let(:tlsa_status) { InternetSecurityEvent::TLSAStatus.new(record, certificate) }

  let(:record) do
    Resolv::DNS::Resource::IN::TLSA.new("\x03\x00\x01\x01\x5a\xd9\xa7\xcb\x61\x43\x17\x33\xb4\x83\xcd\x7e\x15\x5f\x38" \
                                        "\xf7\xa7\x76\xfa\x0e\xf7\xf0\xed\x94\xda\x3c\xa8\xd8\x6c\x21\x0a")
  end

  let(:certificate) { OpenSSL::X509::Certificate.new(File.read('spec/mx.blogreen.org.crt')) }

  context '#to_e' do
    subject { tlsa_status.to_e }

    it { is_expected.to include(state: 'ok') }
  end

  context '#certificate_association_data' do
    it 'computes correct checksums' do
      expect(tlsa_status.certificate_association_data(0, 0)).to eq('3082066930820551a0030201020212035107c642a503567ecfdce5fdc79d1b54903' \
                                                                   '00d06092a864886f70d01010b0500304a310b300906035504061302555331163014' \
                                                                   '060355040a130d4c6574277320456e6372797074312330210603550403131a4c657' \
                                                                   '4277320456e637279707420417574686f72697479205833301e170d313930323031' \
                                                                   '3231353833385a170d3139303530323231353833385a301a3118301606035504031' \
                                                                   '30f6d782e626c6f677265656e2e6f726730820222300d06092a864886f70d010101' \
                                                                   '05000382020f003082020a0282020100c3e484fdd03ea5c77f6e90ebb4fc1f39e76' \
                                                                   '20b1f86fa6ecb6a197db9036d218b32935657f367563e26e8cbb84631e6870236a4' \
                                                                   'ac500bfdc69878d7299f6c4f8b90e8f32b233c80c3d5e55bf7e9c35ca3d7bb93c60' \
                                                                   'fffaf674db56af0f7223366ba160b131058282063f922ae168d3d9d5409647f172d' \
                                                                   '9a79c8d429980df7d757e4b019c4607cc706eecf7eb9f8a58c678a34f96272d1372' \
                                                                   '9e19da9d053ebf390232c6da0aa4f24fc7fc7c05648a11ce0294a94fe4a3149b7ae' \
                                                                   '66ee98f3c59f092cae931c726862d544f9a6d40bc13ecbaac7dcf0c014dac33cce4' \
                                                                   'c9489287ec92770f70eb389275561aa963906cb0f0af8047fb2bcdc04e80864c41c' \
                                                                   'faa978e617e8fb09969bad95bc68ff489600965cc2ae80232ae889d00794ef271cb' \
                                                                   '048f56c6304649159ef2a9e04835d11000d13c686616b9fc44c6c7d8a3229ee4bd4' \
                                                                   '81be35337bb5c6e10206d631255f0fa8ce2e9219bc5809a86ff499661934a8d34aa' \
                                                                   '51760d01404c3666c1eae4efb138c8913c1a507311ae848e0fe077d8f5650d9510c' \
                                                                   'b43f8700226153f8bd1b735b027a2c5460d1aa468226d71acf8b0f0046bcccad9d8' \
                                                                   'db45898f4b07b30bea9b5969ea9731fa7955fc468f22add95059afc2100276ef2cf' \
                                                                   'f1191fdf10d39741a0cf7eee7582bd70e5fa89c6745fc0442fb11bfde1d5b92533e' \
                                                                   '5dacd95a04d1b46aa4964c83d9a0d6b8129709dfcc56e9bd6d50203010001a38202' \
                                                                   '7730820273300e0603551d0f0101ff0404030205a0301d0603551d2504163014060' \
                                                                   '82b0601050507030106082b06010505070302300c0603551d130101ff0402300030' \
                                                                   '1d0603551d0e04160414edec2aad17c9e8947708e0b5fec565be8d90cac7301f060' \
                                                                   '3551d23041830168014a84a6a63047dddbae6d139b7a64565eff3a8eca1306f0608' \
                                                                   '2b0601050507010104633061302e06082b060105050730018622687474703a2f2f6' \
                                                                   'f6373702e696e742d78332e6c657473656e63727970742e6f7267302f06082b0601' \
                                                                   '05050730028623687474703a2f2f636572742e696e742d78332e6c657473656e637' \
                                                                   '27970742e6f72672f30300603551d110429302782146d74612d7374732e626c6f67' \
                                                                   '7265656e2e6f7267820f6d782e626c6f677265656e2e6f7267304c0603551d20044' \
                                                                   '530433008060667810c0102013037060b2b0601040182df13010101302830260608' \
                                                                   '2b06010505070201161a687474703a2f2f6370732e6c657473656e63727970742e6' \
                                                                   'f726730820101060a2b06010401d6790204020481f20481ef00ed007500747eda83' \
                                                                   '31ad331091219cce254f4270c2bffd5e422008c6373579e6107bcc5600000168ab4' \
                                                                   '9104800000403004630440220177dc2a87699c3812c064a01b9157708188b81f830' \
                                                                   '6fda76910e962ae48430910220173dfaeb75565b904b01f6be5fa8d45d5ebd2d6cd' \
                                                                   '14a72d450202b9bea827014007400293c519654c83965baaa50fc5807d4b76fbf58' \
                                                                   '7a2972dca4c30cf4e54547f47800000168ab491055000004030045304302205b8f0' \
                                                                   '382ff41e5caa388bd5908347a312f023023d7bc0ab7c0bfb2061d47bb03021f0ac0' \
                                                                   '8119cdb7dc3b159b7c59fd634481b605346e221b6fe1b06ac14f7f7e2f300d06092' \
                                                                   'a864886f70d01010b0500038201010071abd482a500d7275a0ea58a226a3f8f09fb' \
                                                                   '0a556439f061604bbf0dd93ee5169a3cdd655772d72b60615c2c218c009f46d1bc5' \
                                                                   '4aa31c652a2849ea44b000d62dd9d26da90a688e065fe5e604529fdd84b0f538cc2' \
                                                                   'a107b04e9dcc748137c26a3ab2f8d997105e01a21de24ea81467b49d7e13f217fa8' \
                                                                   'c3c7730e30347e7670219ce6270932f1eed261fb82113f0289418bc14add28f64cb' \
                                                                   '2594bc737bc45c6a221b9811a545152e819f5da0da623ebc9fef20fd0648fe80aa1' \
                                                                   'b5fa3bb755085866d558cc8ae1607486a9c7903cdb5bc8823b5e0d251bfafb64a7b' \
                                                                   'b759633c557cf537c9e89b7b74685b4c0df5f49b2b9efaf122825b60976de04a963' \
                                                                   '5f1373f')
      expect(tlsa_status.certificate_association_data(0, 1)).to eq('015ad9a7cb61431733b483cd7e155f38f7a776fa0ef7f0ed94da3ca8d86c210a')
      expect(tlsa_status.certificate_association_data(0, 2)).to eq('e9278bf56a108dbce0e32dc2366dbb879fb9f3baaaa5c8835c93aec6d5bde2a' \
                                                                   '1b1bc1606347c8b4954b12ff63f730eedcd2d345a08b64e18f0056a6e38ab07' \
                                                                   'ba')
      expect(tlsa_status.certificate_association_data(1, 0)).to eq('30820222300d06092a864886f70d01010105000382020f003082020a0282020100c' \
                                                                   '3e484fdd03ea5c77f6e90ebb4fc1f39e7620b1f86fa6ecb6a197db9036d218b3293' \
                                                                   '5657f367563e26e8cbb84631e6870236a4ac500bfdc69878d7299f6c4f8b90e8f32' \
                                                                   'b233c80c3d5e55bf7e9c35ca3d7bb93c60fffaf674db56af0f7223366ba160b1310' \
                                                                   '58282063f922ae168d3d9d5409647f172d9a79c8d429980df7d757e4b019c4607cc' \
                                                                   '706eecf7eb9f8a58c678a34f96272d13729e19da9d053ebf390232c6da0aa4f24fc' \
                                                                   '7fc7c05648a11ce0294a94fe4a3149b7ae66ee98f3c59f092cae931c726862d544f' \
                                                                   '9a6d40bc13ecbaac7dcf0c014dac33cce4c9489287ec92770f70eb389275561aa96' \
                                                                   '3906cb0f0af8047fb2bcdc04e80864c41cfaa978e617e8fb09969bad95bc68ff489' \
                                                                   '600965cc2ae80232ae889d00794ef271cb048f56c6304649159ef2a9e04835d1100' \
                                                                   '0d13c686616b9fc44c6c7d8a3229ee4bd481be35337bb5c6e10206d631255f0fa8c' \
                                                                   'e2e9219bc5809a86ff499661934a8d34aa51760d01404c3666c1eae4efb138c8913' \
                                                                   'c1a507311ae848e0fe077d8f5650d9510cb43f8700226153f8bd1b735b027a2c546' \
                                                                   '0d1aa468226d71acf8b0f0046bcccad9d8db45898f4b07b30bea9b5969ea9731fa7' \
                                                                   '955fc468f22add95059afc2100276ef2cff1191fdf10d39741a0cf7eee7582bd70e' \
                                                                   '5fa89c6745fc0442fb11bfde1d5b92533e5dacd95a04d1b46aa4964c83d9a0d6b81' \
                                                                   '29709dfcc56e9bd6d50203010001')
      expect(tlsa_status.certificate_association_data(1, 1)).to eq('d8aac0d602e5532136ffb9e368fbc3c9a7a4b694340800b08731bcc09099a925')
      expect(tlsa_status.certificate_association_data(1, 2)).to eq('a7840b0dfc18056727b2bfc1f66f2d6fff91ef8295ea9956b5954fcd3e5c4c8' \
                                                                   '000b29c27b7e9bbc80909984749970604e0fa9fa8a9d0af02011f1b1688514e' \
                                                                   '22')
    end
  end
end
