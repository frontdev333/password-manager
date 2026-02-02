package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
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

var commands = []string{
	"Generate new password",
	"Add new password",
	"Get password",
	"List all passwords",
	"Update password",
	"Delete password",
	"List categories",
	"Show password statistics",
	"Find duplicate passwords",
	"Exit",
}

type Password struct {
	Name         string    `json:"name"`
	Value        string    `json:"value"`
	Category     string    `json:"category"`
	CreatedAt    time.Time `json:"created_at"`
	LastModified time.Time `json:"last_modified"`
}

type PasswordManager struct {
	passwords     map[string]Password `json:"passwords"`
	masterKey     []byte              `json:"-"`
	filePath      string              `json:"-"`
	isInitialized bool                `json:"-"`
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
	if !pm.isInitialized {
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
	if !pm.isInitialized {
		return errors.New(ErrPasswordManagerNotInit)
	}
	file, err := os.Open(pm.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
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

	var initialPasswordName string
	for _, v := range pm.passwords {
		if initialPasswordName == "" {
			initialPasswordName = v.Name
		}
		distrByCat[v.Category]++
	}

	stats["categories"] = distrByCat
	if len(pm.passwords) == 0 {
		return stats
	}
	oldest := pm.passwords[initialPasswordName].CreatedAt
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

func ReadUserInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, err := reader.ReadString('\n')
	if err != nil {
		slog.Error(err.Error())
		return ""
	}

	return strings.TrimSpace(input)
}

func readPassword() (string, error) {
	fmt.Print("[hidden input]")
	bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(bytes)), nil
}

func ShowMainMenu() {
	var cmds strings.Builder
	clearScreen()
	title := "Password Manager\n"
	separationRow := "==========================================\n"
	padding := (utf8.RuneCountInString(separationRow) - utf8.RuneCountInString(title) - 2) / 2

	cmds.WriteString(separationRow)
	cmds.WriteString(strings.Repeat(" ", padding))
	cmds.WriteString(title)
	cmds.WriteString(separationRow)

	fmt.Println(cmds.String())

	cmds.Reset()
	for i, v := range commands {
		if i < 9 {
			i++
		} else {
			i = 0
		}
		cmds.WriteString(fmt.Sprintf("%d. %s\n", i, v))
	}
	cmds.WriteString(separationRow)

	fmt.Println(cmds.String())

}

func PrintPasswordList(passwords []Password) {
	width, _, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		slog.Error(err.Error())
		return
	}
	titles := []string{"Name", "Category", "Created", "Last Modified"}

	lenOfTitles := len(strings.Join(titles, ""))
	padding := (width - lenOfTitles) / len(titles)

	var strBldr strings.Builder

	for _, v := range titles {
		strBldr.WriteString(fmt.Sprintf("%-*s", padding, v))
	}
	lenOfTitlesStr := utf8.RuneCountInString(strBldr.String())
	separationLine := strings.Repeat("-", lenOfTitlesStr)
	strBldr.WriteString(fmt.Sprintf("\n%s", separationLine))

	for _, v := range passwords {
		created := v.CreatedAt.Format("02.01.2006")
		modified := v.LastModified.Format("02.01.2006")
		strBldr.WriteString(fmt.Sprintf("\n%-*s%-*s%-*s%-*s", padding, v.Name, padding, v.Category, padding, created, padding, modified))
	}

	fmt.Println(strBldr.String())
}

func ShowPasswordDetails(password Password) {
	fmt.Println("Service:", password.Name)
	fmt.Println("Category:", password.Category)
	fmt.Println("Password:", password.Value)
	fmt.Println("Created:", password.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Println("Last Modified:", password.LastModified.Format("2006-01-02 15:04:05"))
}

func waitForEnter() {
	fmt.Println("Press Enter to continue...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func HandlePasswordGeneration(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Password Generation ===")

	length, err := strconv.Atoi(ReadUserInput("Enter password length (min 8): "))
	if err != nil {
		return err
	}

	pass, err := pm.GeneratePassword(length)
	if err != nil {
		return err
	}

	fmt.Println("Generated password:", pass)
	showMessage("✓ Success: Password generated successfully", statusSuccess)
	waitForEnter()
	return nil

}

func HandlePasswordAdd(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Add New Password ===")
	serviceName := ReadUserInput("Enter service name: ")

	fmt.Print("Enter password (or press Enter to generate): ")
	pass, err := readPassword()
	if err != nil {
		return err
	}

	if pass == "" {
		pass, err = pm.GeneratePassword(8)
		if err != nil {
			return err
		}
		showMessage(fmt.Sprintf("\n→ Info: Generated password: %s", pass), statusInfo)
	}

	category := ReadUserInput("\nEnter category: ")

	if err = pm.SavePassword(serviceName, pass, category); err != nil {
		return err
	}

	showMessage("✓ Success: Password saved successfully", statusSuccess)
	waitForEnter()
	return nil
}

func HandlePasswordSearch(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Search Password ===")
	serviceName := ReadUserInput("Enter service name: ")

	pass, err := pm.GetPassword(serviceName)
	if err != nil {
		return err
	}

	ShowPasswordDetails(pass)
	waitForEnter()
	return nil
}

func HandlePasswordUpdate(pm *PasswordManager) error {
	service := ReadUserInput("Enter the name of service")
	fmt.Print("Enter new password please: ")
	pass, err := readPassword()
	if err != nil {
		return err
	}
	if err = pm.UpdatePassword(service, pass); err != nil {
		return err
	}
	updatedPass, err := pm.GetPassword(service)
	if err != nil {
		return err
	}
	ShowPasswordDetails(updatedPass)
	waitForEnter()

	return nil
}

func HandlePasswordDelete(pm *PasswordManager) error {
	service := ReadUserInput("Enter the name of service")
	if err := pm.DeletePassword(service); err != nil {
		return err
	}
	showMessage("✓ Success: Password deleted successfully", statusSuccess)
	return nil
}

func HandleExitAndSave(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Saving and Exiting ===")
	err := pm.SaveToFile()
	fmt.Println("Saving changes...")
	if err != nil {
		showMessage(fmt.Sprintf("✗ Error: %v", err), statusError)
		return err
	}
	showMessage("✓ Success: Changes saved successfully!", statusSuccess)
	showMessage("✓ Success: Goodbye!", statusSuccess)
	return nil
}

func main() {
	pm := NewPasswordManager("test.dat")
	fmt.Println("=== Password Manager Initialization ===")
	fmt.Print("Enter master password: ")
	pass, err := readPassword()
	if err != nil {
		showMessage(fmt.Sprintf("Error reading master password: %v", err), statusError)
		return
	}

	if err = pm.SetMasterPassword(pass); err != nil {
		showMessage(fmt.Sprintf("Error setting master password: %v", err), statusError)
		return
	}

	if err = pm.LoadFromFile(); err != nil {
		showMessage(fmt.Sprintf("Error loading data: %v", err), statusError)
		return
	}

	showMessage("Password manager initialized successfully", statusSuccess)

	waitForEnter()

	for {
		ShowMainMenu()
		choice := ReadUserInput("Enter your choice: ")
		switch choice {
		case "1":
			err = HandlePasswordGeneration(pm)
		case "2":
			err = HandlePasswordAdd(pm)
		case "3":
			err = HandlePasswordSearch(pm)
		case "4":
			PrintPasswordList(slices.Collect(maps.Values(pm.passwords)))
		case "5":
			err = HandlePasswordUpdate(pm)
		case "6":
			err = HandlePasswordDelete(pm)
		case "7":
			fmt.Println(pm.ListCategories())
		case "8":
			fmt.Println(pm.GetPasswordStats())
		case "9":
			fmt.Println(pm.FindDuplicatePasswords())
		case "0":
			clearScreen()
			fmt.Println("=== Saving and Exiting ===")
			err = HandleExitAndSave(pm)
			if err != nil {
				showMessage(fmt.Sprintf("Error during exit: %v", err), statusError)
				waitForEnter()
				return
			}
			showMessage("Goodbye!", statusSuccess)
			return
		default:
			showMessage("Invalid choice. Please try again", statusError)
			waitForEnter()
		}

		if err != nil {
			showMessage(err.Error(), statusError)
			waitForEnter()
		}
	}

}
