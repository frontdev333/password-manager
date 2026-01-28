package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Password struct {
	Name         string     `json:"name"`          // Название сервиса или сайта
	Value        string     `json:"value"`         // Значение пароля
	Category     string     `json:"category"`      // Категория для группировки (например: "social", "work", "finance")
	CreatedAt    time.Time  `json:"created_at"`    // Дата создания записи
	LastModified *time.Time `json:"last_modified"` // Дата последнего изменения
}

type PasswordManager struct {
	passwords     map[string]Password `json:"passwords"` // Хранилище паролей, где ключ - название сервиса
	masterKey     []byte              `json:"-"`         // Главный ключ шифрования, используется для защиты всех паролей
	filePath      string              `json:"-"`         // Путь к файлу для хранения зашифрованных данных
	isInitialized bool                `json:"-"`         // Флаг, показывающий установлен ли мастер-пароль
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
		return "", errors.New("password length must be at least 8 characters")
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

//func (pm *PasswordManager) SavePassword(name, value, category string) error {
//	if pm.isInitialized != true {
//		return errors.New("password manager is not initialized")
//	}
//
//	_, ok := pm.passwords[name]
//	if ok {
//		return errors.New("password for this service already exists in Password Manager's store")
//	}
//
//	pass := NewPa
//
//}

func main() {
	pm := NewPasswordManager("test.dat")

	// Генерация валидного пароля
	password, err := pm.GeneratePassword(12)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Generated password: %s\n", password)
	}

	// Попытка сгенерировать слишком короткий пароль
	_, err = pm.GeneratePassword(4)
	fmt.Printf("Error for short password: %v\n", err)
}
