class Awscurl < Formula
  include Language::Python::Virtualenv

  desc "Curl like simplicity to access AWS resources with AWS Signature Version 4 request signing."
  homepage "https://github.com/okigan/awscurl"
  url "https://github.com/okigan/awscurl/archive/v0.19.tar.gz"
  sha256 "fa31932a79bee92e5c4a4754bf6e0c4868fa21db3659ea23d4d9f6b3eb9f367e"
  head "https://github.com/okigan/awscurl.git"

  # TODO: If you're submitting an existing package, make sure you include your
  #       bottle block here.

  depends_on :python3

  resource "configargparse" do
    url "https://files.pythonhosted.org/packages/ee/e2/d392af39dfe241e9fa5e9830ea1f00c077c7ae1dd6ede97cba06404c66fb/ConfigArgParse-0.15.2.tar.gz#sha256=558738aff623d6667aa5b85df6093ad3828867de8a82b66a6d458fb42567beb3"
    sha256 "558738aff623d6667aa5b85df6093ad3828867de8a82b66a6d458fb42567beb3"
  end

  resource "configparser" do
    url "https://files.pythonhosted.org/packages/7a/2a/95ed0501cf5d8709490b1d3a3f9b5cf340da6c433f896bbe9ce08dbe6785/configparser-4.0.2-py2.py3-none-any.whl#sha256=254c1d9c79f60c45dfde850850883d5aaa7f19a23f13561243a050d5a7c3fe4c"
    sha256 "254c1d9c79f60c45dfde850850883d5aaa7f19a23f13561243a050d5a7c3fe4c"
  end

  resource "certifi" do
    url "https://files.pythonhosted.org/packages/b9/63/df50cac98ea0d5b006c55a399c3bf1db9da7b5a24de7890bc9cfd5dd9e99/certifi-2019.11.28-py2.py3-none-any.whl#sha256=017c25db2a153ce562900032d5bc68e9f191e44e9a0f762f373977de9df1fbb3"
    sha256 "017c25db2a153ce562900032d5bc68e9f191e44e9a0f762f373977de9df1fbb3"
  end

  resource "chardet" do
    url "https://files.pythonhosted.org/packages/bc/a9/01ffebfb562e4274b6487b4bb1ddec7ca55ec7510b22e4c51f14098443b8/chardet-3.0.4-py2.py3-none-any.whl#sha256=fc323ffcaeaed0e0a02bf4d117757b98aed530d9ed4531e3e15460124c106691"
    sha256 "fc323ffcaeaed0e0a02bf4d117757b98aed530d9ed4531e3e15460124c106691"
  end

  resource "idna" do
    url "https://files.pythonhosted.org/packages/14/2c/cd551d81dbe15200be1cf41cd03869a46fe7226e7450af7a6545bfc474c9/idna-2.8-py2.py3-none-any.whl#sha256=ea8b7f6188e6fa117537c3df7da9fc686d485087abf6ac197f9c46432f7e4a3c"
    sha256 "ea8b7f6188e6fa117537c3df7da9fc686d485087abf6ac197f9c46432f7e4a3c"
  end

  resource "urllib3" do
    url "https://files.pythonhosted.org/packages/b4/40/a9837291310ee1ccc242ceb6ebfd9eb21539649f193a7c8c86ba15b98539/urllib3-1.25.7-py2.py3-none-any.whl#sha256=a8a318824cc77d1fd4b2bec2ded92646630d7fe8619497b142c84a9e6f5a7293"
    sha256 "a8a318824cc77d1fd4b2bec2ded92646630d7fe8619497b142c84a9e6f5a7293"
  end

  def install
    virtualenv_install_with_resources
  end

  # TODO: Add your package's tests here
end