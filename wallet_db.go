package cardano

type WalletDB interface {
	SaveWallet(*Wallet) error
	GetWallets() ([]Wallet, error)
	DeleteWallet(WalletID) error
	Close()
}