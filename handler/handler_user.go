package handler

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	config "go-jwt/config"
	driver "go-jwt/driver"
	models "go-jwt/model"
	repoImpl "go-jwt/repository/repoimpl"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("abcdefghijklmnopq")

type Claims struct {
	Name string `json:"name"`
	jwt.StandardClaims
}

func Register(w http.ResponseWriter, r *http.Request) {
	var regData models.RegistrationData
	err := json.NewDecoder(r.Body).Decode(&regData)
	if err != nil {
		ResponseErrMiddlware(w, http.StatusBadRequest)
		return
	}

	_, err = repoImpl.NewUserRepo(driver.Mongo.Client.
		Database(config.DB_NAME)).
		FindUserByEmail(regData.Name)

	if err != models.ERR_USER_NOT_FOUND {
		ResponseErrMiddlware(w, http.StatusConflict)
		return
	}

	user := models.User{
		Name: regData.Name,
	}
	err = repoImpl.NewUserRepo(driver.Mongo.Client.
		Database(config.DB_NAME)).Insert(user)
	if err != nil {
		ResponseErrMiddlware(w, http.StatusInternalServerError)
		return
	}

	var tokenString string
	tokenString, err = GenToken(user)
	if err != nil {
		ResponseErrMiddlware(w, http.StatusInternalServerError)
		return
	}

	ResponseOkMiddleware(w, models.RegisterResponse{
		Token:  tokenString,
		Status: http.StatusOK,
	})
}

func Login(w http.ResponseWriter, r *http.Request) {
	var loginData models.LoginData
	err := json.NewDecoder(r.Body).Decode(&loginData)
	if err != nil {
		ResponseErrMiddlware(w, http.StatusBadRequest)
		return
	}

	var user models.User
	user, err = repoImpl.NewUserRepo(driver.Mongo.Client.
		Database(config.DB_NAME)).
		CheckLoginInfo(loginData.Name)
	if err != nil {
		ResponseErrMiddlware(w, http.StatusUnauthorized)
		return
	}

	var tokenString string
	tokenString, err = GenToken(user)
	if err != nil {
		ResponseErrMiddlware(w, http.StatusInternalServerError)
		return
	}

	ciphertext := encrypt([]byte(tokenString), string(jwtKey))
	var encrypted interface{}
	plaintext := decrypt(ciphertext, string(jwtKey))
	decrypted := string(plaintext)

	// switch case theo encoder request client gửi lên để response (hexstring, byte, base64)
	// convert data
	switch loginData.Encoder {
	case "hex":
		// []byte to hexstring
		encrypted = fmt.Sprintf("%x", ciphertext)
	case "byte":
		// []byte
		encrypted = ciphertext
	case "base64":
		// []byte to base64
		encrypted = b64.StdEncoding.EncodeToString(ciphertext)
	case "hungnhieudat":
		// []byte to hungnhieudat
		encrypted = string(ciphertext)
	}

	ResponseOkMiddleware(w, models.RegisterResponse{
		Token:  tokenString,
		Enc:    encrypted,
		Dec:    decrypted,
		Status: http.StatusOK,
	})

	fmt.Println("Encrypted: ", encrypted)
	fmt.Printf("Format: %T\n", encrypted)
	fmt.Println("Decrypted: ", decrypted)
	fmt.Printf("Format: %T\n", decrypted)
	fmt.Println("=====>")
}

func GetUser(w http.ResponseWriter, r *http.Request) {
	tokenHeader := r.Header.Get("Authorization")

	if tokenHeader == "" {
		ResponseErrMiddlware(w, http.StatusForbidden)
		return
	}

	splitted := strings.Split(tokenHeader, " ") // Bearer jwt_token
	if len(splitted) != 2 {
		ResponseErrMiddlware(w, http.StatusForbidden)
		return
	}

	tokenPart := splitted[1]
	tk := &Claims{}

	token, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		fmt.Println(err)
		ResponseErrMiddlware(w, http.StatusInternalServerError)
		return
	}

	if token.Valid {
		ResponseOkMiddleware(w, token.Claims)
	}
}

func GenToken(user models.User) (string, error) {
	expirationTime := time.Now().Add(10 * time.Minute)
	claims := &Claims{
		Name: user.Name,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func ResponseErrMiddlware(w http.ResponseWriter, statusCode int) {
	jData, err := json.Marshal(models.Error{
		Status:  statusCode,
		Message: http.StatusText(statusCode),
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jData)
}

func ResponseOkMiddleware(w http.ResponseWriter, data interface{}) {
	if data == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	jData, err := json.Marshal(data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jData)
}
