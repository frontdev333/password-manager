package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	ErrWeakPassword           = "password length must be at least 8 characters"
	ErrPasswordManagerNotInit = "password manager is not initialized"
	ErrPasswordNotFound       = "password not found"
	statusSuccess             = "success"
	statusError               = "error"
	statusInfo                = "info"
	statusWait                = "wait"
	colorRed                  = "\033[31m"
	colorGreen                = "\033[32m"
	colorYellow               = "\033[33m"
	colorReset                = "\033[0m"
)

type Password struct {
	Name         string    `json:"name"`          // Название сервиса или сайта
	Value        string    `json:"value"`         // Значение пароля
	Category     string    `json:"category"`      // Категория для группировки (например: "social", "work", "finance")
	CreatedAt    time.Time `json:"created_at"`    // Дата создания записи
	LastModified time.Time `json:"last_modified"` // Дата последнего изменения
}

type PasswordManager struct {
	passwords     map[string]Password `json:"passwords"` // Хранилище паролей, где ключ - название сервиса
	masterKey     []byte              `json:"-"`         // Главный ключ шифрования, используется для защиты всех паролей
	filePath      string              `json:"-"`         // Путь к файлу для хранения зашифрованных данных
	isInitialized bool                `json:"-"`         // Флаг, показывающий установлен ли мастер-пароль
}

func NewPassword(name, value, category string) Password {
	return Password{
		Name:         name,
		Value:        value,
		Category:     category,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
}

func NewPasswordManager(filePath string) *PasswordManager {
	return &PasswordManager{
		passwords:     make(map[string]Password),
		masterKey:     nil,
		filePath:      filePath,
		isInitialized: false,
	}
}

func (pm *PasswordManager) GeneratePassword(length int) (string, error) {
	if length < 8 {
		return "", errors.New(ErrWeakPassword)
	}

	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()[]{}';:,./\\`=-"
	const charsLen = len(chars)
	randBytes := make([]byte, length)

	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}

	var result strings.Builder

	for _, v := range randBytes {
		i := int(v) % charsLen
		result.WriteByte(chars[i])
	}
	return result.String(), nil
}

func (pm *PasswordManager) SavePassword(name, value, category string) error {
	if pm.isInitialized != true {
		return errors.New(ErrPasswordManagerNotInit)
	}

	_, ok := pm.passwords[name]
	if ok {
		return errors.New("password for this service already exists")
	}

	pass := NewPassword(name, value, category)
	pm.passwords[name] = pass

	return nil

}

func (pm *PasswordManager) GetPassword(name string) (Password, error) {
	if !pm.isInitialized {
		return Password{}, errors.New(ErrPasswordManagerNotInit)
	}

	pass, ok := pm.passwords[name]
	if !ok {
		return Password{}, errors.New(ErrPasswordNotFound)
	}
	return pass, nil
}

func (pm *PasswordManager) ListPasswords() []Password {
	tmpPassSlice := make([]Password, 0, len(pm.passwords))

	for _, v := range pm.passwords {
		tmpPassSlice = append(tmpPassSlice, v)
	}

	return tmpPassSlice
}

func (pm *PasswordManager) SetMasterPassword(masterPassword string) error {
	if len(masterPassword) < 8 {
		return errors.New(ErrWeakPassword)
	}

	keyBytes := make([]byte, 32)

	copy(keyBytes, []byte(masterPassword))

	pm.masterKey = keyBytes
	pm.isInitialized = true

	return nil
}

func (pm *PasswordManager) SaveToFile() error {
	if !pm.isInitialized {
		return errors.New(ErrPasswordManagerNotInit)
	}

	data, err := json.Marshal(pm.passwords)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	encryptedData := make([]byte, len(data))
	stream.XORKeyStream(encryptedData, data)

	file, err := os.Create(pm.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err = file.Write(iv); err != nil {
		return err
	}

	if _, err = file.Write(encryptedData); err != nil {
		return err
	}

	return nil
}

func (pm *PasswordManager) LoadFromFile() error {
	file, err := os.Open(pm.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(file, iv); err != nil {
		return err
	}

	encryptedData, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return err
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	decryptedData := make([]byte, len(encryptedData))
	stream.XORKeyStream(decryptedData, encryptedData)

	return json.Unmarshal(decryptedData, &pm.passwords)
}

func (pm *PasswordManager) CheckPasswordStrength(password string) error {
	if len(password) < 8 {
		return errors.New(ErrWeakPassword)
	}

	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasNumber = true
		case strings.ContainsRune("!@#$%^&*", char):
			hasSpecial = true
		}
	}

	if hasUpper && hasLower && hasNumber && hasSpecial {
		return nil
	}

	return errors.New("password is too weak")
}

func (pm *PasswordManager) GetPasswordsByCategory(category string) []Password {
	var res []Password

	for _, v := range pm.passwords {
		if v.Category == category {
			res = append(res, v)
		}
	}

	return res
}

func (pm *PasswordManager) FindDuplicatePasswords() map[string][]string {
	groups := make(map[string][]string)
	duplicates := make(map[string][]string)

	for _, v := range pm.passwords {
		groups[v.Value] = append(groups[v.Value], v.Name)
	}

	for k, v := range groups {
		if len(v) > 1 {
			duplicates[k] = v
		}
	}

	return duplicates
}

func (pm *PasswordManager) UpdatePassword(name, newValue string) error {
	if !pm.isInitialized {
		return errors.New(ErrPasswordManagerNotInit)
	}

	pass, ok := pm.passwords[name]
	if !ok {
		return errors.New(ErrPasswordNotFound)
	}

	if err := pm.CheckPasswordStrength(newValue); err != nil {
		return err
	}

	pass.Value = newValue
	pass.LastModified = time.Now()

	pm.passwords[name] = pass

	return nil
}

func (pm *PasswordManager) DeletePassword(name string) error {
	if !pm.isInitialized {
		return errors.New(ErrPasswordManagerNotInit)
	}

	if _, ok := pm.passwords[name]; !ok {
		return errors.New(ErrPasswordNotFound)
	}

	delete(pm.passwords, name)
	return nil
}

func (pm *PasswordManager) ListCategories() []string {
	categories := make(map[string]bool)

	for _, v := range pm.passwords {
		if _, ok := categories[v.Category]; ok {
			continue
		}
		categories[v.Category] = true
	}
	result := make([]string, len(categories))

	i := 0
	for k, _ := range categories {
		result[i] = k
		i++
	}

	return result
}

func (pm *PasswordManager) GetPasswordStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["total_passwords"] = len(pm.passwords)

	categories := pm.ListCategories()
	distrByCat := make(map[string]int, len(categories))

	var randPassName string
	for _, v := range pm.passwords {
		if randPassName == "" {
			randPassName = v.Name
		}
		distrByCat[v.Category]++
	}

	stats["categories"] = distrByCat

	oldest := pm.passwords[randPassName].CreatedAt
	newest := oldest
	for _, v := range pm.passwords {
		if oldest.After(v.CreatedAt) {
			oldest = v.CreatedAt
		}
		if newest.Before(v.CreatedAt) {
			newest = v.CreatedAt
		}
	}

	stats["oldest_password_date"] = oldest
	stats["newest_password_date"] = newest

	return stats
}

func clearScreen() {
	fmt.Println("[Screen is cleaning]")
	fmt.Print("\033[H\033[2J")
}

func waitForEnter() {
	fmt.Println("Press Enter to continue...")
}

func showMessage(message string, status string) {
	var color string
	switch status {
	case statusSuccess:
		color = colorGreen
	case statusError:
		color = colorRed
	case statusInfo:
		color = colorYellow
	default:
		fmt.Println(message)
		return
	}
	fmt.Printf("%s%s%s\n", color, message, colorReset)
}

func main() {
	// Очищаем экран и показываем разные типы сообщений
	clearScreen()
	fmt.Println("=== Testing UI functions ===\n")

	showMessage("Password saved successfully", statusSuccess)
	showMessage("Invalid data format", statusError)
	showMessage("Press Enter to continue", statusInfo)

	fmt.Println("\nNow it's time to pause...")
	waitForEnter()

	clearScreen()
	fmt.Println("Screen cleared!")
}
