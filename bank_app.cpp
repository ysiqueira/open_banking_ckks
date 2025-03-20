/*

Yaissa Campos Siqueira

*/
#include <iostream>
#include <vector>
#include <map>
#include <chrono>
#include <iomanip>
#include <helib/helib.h>
#include <sstream>

using namespace helib;
using namespace std;

struct Bank {
    std::string name;
};

struct Transaction {
    helib::Ctxt encryptedBankName;
    helib::Ctxt encryptedDate;
    helib::Ctxt encryptedAmount;
    std::string type;
};

struct User {
    const helib::PubKey& publicKey;
    helib::SecKey secretKey;
    std::map<std::string, Bank> registeredBanks;
    std::vector<Transaction> transactions;

    User(const helib::PubKey& pubKey, helib::SecKey secKey) : 
                    publicKey(pubKey), secretKey(secKey) {}

};


class OpenBankingAPI {
public:
    static std::unique_ptr<OpenBankingAPI> Create()
        {
            return std::unique_ptr<OpenBankingAPI>(new OpenBankingAPI(5));
        };

    OpenBankingAPI(const OpenBankingAPI&) = delete;
    OpenBankingAPI& operator =(const OpenBankingAPI&) = delete;
    
    std::tuple<const helib::PubKey&, helib::SecKey> generateKeys() {
        long n = context_.getNSlots();
        SecKey secretKey(context_);
        secretKey.GenSecKey();
        const PubKey& publicKey = secretKey;
        return std::tuple(publicKey, secretKey);
    }

    helib::SecKey generateSecurityKey() {
        long n = context_.getNSlots();
        SecKey secretKey(context_);
        secretKey.GenSecKey();
        return secretKey;
    }

    helib::PubKey generatePublicKey(helib::SecKey sk) {
        const PubKey& publicKey =sk;
        return publicKey;
    }
    
    void registerBank(User& user, const Bank& bank) {
        user.registeredBanks[bank.name] = bank;
    }

    vector<double> decrypt(const User& user, const helib::Ctxt& ciphertext) {
        helib::PtxtArray plaintext(context_);
        plaintext.decrypt(ciphertext, user.secretKey);
        vector<double> v;
        plaintext.store(v);
        return v;
    }

    double decryptDouble(const User& user, const helib::Ctxt& ciphertext) {
        return decrypt(user, {ciphertext})[0];
    }


   std::string decryptString(const User& user, const helib::Ctxt& ciphertext) {
        helib::PtxtArray plaintext(context_);
        plaintext.decrypt(ciphertext, user.secretKey);
        vector<double> v;
        plaintext.store(v);

        std::string result;
        for (long i = 0; i < v.size(); ++i) {
            result += static_cast<char>(v[i]);
        }
        return result;
    }

    bool isEqualEncrypted(User& user, const helib::Ctxt& ctx1, const helib::Ctxt& ctx2){
        auto res = decryptDouble(user, encryptedDoubleEquality(ctx1, 
        ctx2, user.publicKey));
        cout << res << " res \n";
        return res <= 0;
    }
    
    void addTransaction(User& user, const Transaction& transaction) {
        user.transactions.push_back(transaction);
        bootstrap(user,transaction.encryptedAmount);

    }

    void deposit(User& user, const std::string& bankName, std::chrono::system_clock::time_point date, double amount) {
        Transaction transaction = {
            encryptString(user, bankName),
            encryptString(user, std::to_string(std::chrono::system_clock::to_time_t(date))),
            encrypt(user, { amount} ),
            "deposit"
        };
        addTransaction(user, transaction);
    }

    void withdraw(User& user, const std::string& bankName, std::chrono::system_clock::time_point date, double amount) {
        Transaction transaction = {
            encryptString(user, bankName),
            encryptString(user, std::to_string(std::chrono::system_clock::to_time_t(date))),
            encrypt(user, {amount} ),
            "withdrawal"
        };
        addTransaction(user, transaction);
    }

    void savings(User& user, const std::string& bankName, std::chrono::system_clock::time_point date, double amount, double interestRate) {
        helib::Ctxt encryptedAmount = encrypt(user, {amount});
        helib::Ctxt encryptedInterestRate = encryptDouble(user, 1.0 + interestRate);
        helib::Ctxt encryptedIncome = multiply(encryptedAmount, encryptedInterestRate);
        double income = decryptDouble(user, {encryptedIncome});
        Transaction transaction = {
            encryptString(user, bankName),
            encryptString(user, std::to_string(std::chrono::system_clock::to_time_t(date))),
            encryptedIncome,
            "savings"
        };
        addTransaction(user, transaction);
    }

    std::vector<Transaction> searchTransactions( User& user, const std::string& bankName, std::chrono::system_clock::time_point startDate, std::chrono::system_clock::time_point endDate) {
        std::vector<Transaction> results;

        auto encryptedBank = encryptString(user, bankName);
      
        for (const auto& transaction : user.transactions) {
            //cout << decryptString(user, transaction.encryptedBankName) << "\n";
            
            bool isEqualBank = isEqualEncrypted(user, transaction.encryptedBankName,encryptedBank);
            std::time_t decryptedTime = std::stoll(decryptString(user, transaction.encryptedDate));
            std::chrono::system_clock::time_point transactionDate = std::chrono::system_clock::from_time_t(decryptedTime);
            
            //std::cout << std::put_time(std::localtime(&decryptedTime), "%Y-%m-%d %H:%M:%S") << "\n";
            
            if (isEqualBank && transactionDate >= startDate && transactionDate <= endDate) {
                results.push_back(transaction);
            }
        }
        return results;
    }

    helib::Ctxt getTotalBalance(const User& user) {
        auto totalBalance = encryptDouble(user,0.0);
        for (const auto& transaction : user.transactions) {
            totalBalance += transaction.encryptedAmount;
        }
        return totalBalance;
    }
    
private:
    explicit OpenBankingAPI(int bootstrapThreshold) : context_(helib::ContextBuilder<helib::CKKS>()
                                .m(32 * 1024).bits(358).precision(30).c(6)
                                .build()),
                                bootstrapThreshold_(bootstrapThreshold) {}
    helib::Context context_;
    int bootstrapThreshold_;

    helib::Ctxt encrypt(const User& user, const vector<double> value) {
        long n = context_.getNSlots();

        vector<double> v0(n, 0.0);
        for (long i = 0; i < value.size(); i++){
            v0[i] = value[i]*1.0;
        }

        PtxtArray p0(context_, v0);
        helib::Ctxt c0(user.publicKey);
        p0.encrypt(c0);
        return c0;
    }

    helib::Ctxt encryptDouble(const User& user, const double value) {
        return encrypt(user, {value});
    }

    helib::Ctxt encryptString(const User& user, const std::string& value) {
        vector<double> v0(value.size());
        for (size_t i = 0; i < value.size(); ++i) {
            v0[i] = static_cast<double>(value[i]);
        }
        return encrypt(user, v0);
    }

    helib::Ctxt add(const helib::Ctxt& ctxt1, const helib::Ctxt& ctxt2) {
        helib::Ctxt result = ctxt1;
        result += ctxt2;
        return result;
    }

    helib::Ctxt multiply(const helib::Ctxt& ctxt1, const helib::Ctxt& ctxt2) {
        helib::Ctxt result = ctxt1;
        result *= ctxt2;
        return result;
    }

    // Function to compare two encrypted doubles for equality
    helib::Ctxt encryptedDoubleEquality(const helib::Ctxt& ctx1, const helib::Ctxt& ctx2, 
                    const helib::PubKey& publicKey) {
        // Subtract the two encrypted values
        helib::Ctxt difference = ctx1;
        difference -= ctx2;

        // Encrypt 0
        std::vector<double> zero_ptxt(context_.getNSlots(), 0.0);
        helib::PtxtArray zero_ptxt_array(context_, zero_ptxt);
        helib::Ctxt encrypted_zero(publicKey);
        zero_ptxt_array.encrypt(encrypted_zero);

        // Encrypt 1
        std::vector<double> one_ptxt(context_.getNSlots(), 1.0);
        helib::PtxtArray one_ptxt_array(context_, one_ptxt);
        helib::Ctxt encrypted_one(publicKey);
        one_ptxt_array.encrypt(encrypted_one);

        // Compute the absolute value of the difference (approximate)
        difference.square(); // Square to approximate absolute value
        //difference.sqrt(); // Square root to get back to original scale (approximate)

        // Compare the squared difference with a small threshold (e.g., 1e-6)
        double threshold = 1e-6;
        std::vector<double> threshold_ptxt(context_.getNSlots(), threshold);
        helib::PtxtArray threshold_ptxt_array(context_, threshold_ptxt);
        helib::Ctxt encrypted_threshold(publicKey);
        threshold_ptxt_array.encrypt(encrypted_threshold);

        // Compute the difference between the squared difference and the threshold
        helib::Ctxt comparison = difference;
        comparison -= encrypted_threshold;

        // If the difference is negative or close to zero, it means the values are equal.
        // If the difference is positive, it means the values are not equal.

        //If the difference is small, then return 1, else return 0.
        //This is a polynomial approximation of a boolean function.

        //TODO: FIX APPROXIMATION TO CLOSE TO ZERO
        helib::Ctxt result = encrypted_one; // Default: not equal
        comparison.negate(); 
        comparison += 1.0;
        comparison.square();
        comparison -= 1.0;
        comparison.negate();

        cout << "c.capacity=" << comparison.capacity() << " ";
        cout << "c.errorBound=" << comparison.errorBound() << "\n";
        
        result.multiplyBy(comparison);
        result += encrypted_zero;
        return result;
    }

    void bootstrap(User& user, helib::Ctxt ciphertext) {
        if(ciphertext.capacity() < bootstrapThreshold_){
            cout << "Please Bootstrap!\n";
        }
    }

};

int main() {
    
    auto api = OpenBankingAPI::Create();
        
    helib::SecKey secKey = api->generateSecurityKey();
    helib::PubKey pk= api->generatePublicKey(secKey);
    User user(pk, secKey);
    
    Bank bank1 = {"Bank of Example"};
    api->registerBank(user, bank1);

    auto now = std::chrono::system_clock::now();
    auto yesterday = now - std::chrono::hours(24);
  
    api->deposit(user, "Bank of Example", now, 100.0);  
    api->withdraw(user, "Bank of Example", now, 50.0);
    api->savings(user, "Bank of Example", now, 50.0, 0.05);
    
    api->deposit(user, "Bank of Example", now, 25.0);
    api->withdraw(user, "Bank of Example", now, 10.0);
    api->deposit(user, "Bank of Crazy", now, 10.0);

    const std::string& query = "Bank of Crazy";
    auto transactions = api->searchTransactions(user,query, yesterday, now);

    std::cout << "Transactions:\n";
    for (const auto& transaction : transactions) {
        std::string decryptedBank = api->decryptString(user, transaction.encryptedBankName);
        std::time_t decryptedTime = std::stoll(api->decryptString(user, transaction.encryptedDate));
        std::chrono::system_clock::time_point transactionDate = std::chrono::system_clock::from_time_t(decryptedTime);
        double decryptedAmount = api->decryptDouble(user, transaction.encryptedAmount);

        std::time_t t = std::chrono::system_clock::to_time_t(transactionDate);
        std::cout << "  " << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S") << " - " << transaction.type << ": " << decryptedAmount << "\n";
    }

    std::cout << "Total Balance: " << api->decryptDouble(user,api->getTotalBalance(user)) << "\n";

    return 0;
}
