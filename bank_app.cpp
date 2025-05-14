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

        std::string result = "";
        for (long i = 0; i < v.size(); ++i) {
            result += static_cast<char>(round(v[i]));
        }
        return result;
    }

    bool isEqualDoubleEncrypted(User& user, const helib::Ctxt& ctx1, const helib::Ctxt& ctx2){
        return encryptedDoubleEquality(ctx1, ctx2, user);
    }

    bool isEqualStringEncrypted(User& user, const helib::Ctxt& ctx1, const helib::Ctxt& ctx2){
        return decryptString(user, ctx1) == decryptString(user, ctx2);
    }
    
    void addTransaction(User& user, const Transaction& transaction) {
        auto encryptedAmount = bootstrap(user,transaction.encryptedAmount);
        user.transactions.push_back({
            transaction.encryptedBankName, 
            transaction.encryptedDate,
            encryptedAmount, 
            transaction.type });
         

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

    std::vector<Transaction> searchTransactionsByBank( User& user, 
        const std::string& bankName) {
        std::vector<Transaction> results;

        auto encryptedBank = encryptString(user, bankName);
      
        for (const auto& transaction : user.transactions) {
            bool isEqualBank = isEqualStringEncrypted(user, transaction.encryptedBankName,encryptedBank);
                        
            if (isEqualBank) {
                results.push_back(transaction);
            }
        }
        return results;
    }

    std::vector<Transaction> searchTransactionsByDates( User& user,
        std::chrono::system_clock::time_point startDate, 
        std::chrono::system_clock::time_point endDate) {
        std::vector<Transaction> results;
      
        for (const auto& transaction : user.transactions) {
            std::time_t decryptedTime = std::stoll(decryptString(user, transaction.encryptedDate));
            std::chrono::system_clock::time_point transactionDate = std::chrono::system_clock::from_time_t(decryptedTime);
                        
            if (transactionDate >= startDate && transactionDate <= endDate) {
                results.push_back(transaction);
            }
        }
        return results;
    }

    std::vector<Transaction> searchTransactionsByValue( User& user, const double& value) {
        std::vector<Transaction> results;

        auto encryptedValue = encryptDouble(user, value);
      
        for (const auto& transaction : user.transactions) {
            bool isEqualValue = isEqualDoubleEncrypted(user, transaction.encryptedAmount, encryptedValue);

            if (isEqualValue) {
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
    
private:
    explicit OpenBankingAPI(int bootstrapThreshold) : context_(helib::ContextBuilder<helib::CKKS>()
                                .m(32 * 1024).bits(358).precision(30).c(6)
                                .build()),
                                bootstrapThreshold_(bootstrapThreshold) {}
    helib::Context context_;
    int bootstrapThreshold_;
    double equality_threshold_ = 0.00001;

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
    bool encryptedDoubleEquality(const helib::Ctxt& ctx1, const helib::Ctxt& ctx2, 
                    const User& user) {
        // Subtract the two encrypted values
        helib::Ctxt difference = ctx1;
        difference -= ctx2;

        double res = decryptDouble(user, difference);

        return (abs(res) <= equality_threshold_);
    }

    helib::Ctxt bootstrap(User& user, helib::Ctxt ciphertext) {
        if(ciphertext.capacity() < bootstrapThreshold_){
            cout << "Please Bootstrap!\n";
            auto dec = decryptDouble(user,ciphertext);
            return encryptDouble(user, dec);
        }
        return ciphertext;
    }

};

void testFunctionalities(){
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
    api->savings(user, "Bank of Test", now, 50.0, 0.05);
    
    api->deposit(user, "Bank of Example", now, 25.0);
    api->withdraw(user, "Bank of Example", now, 10.0);
    api->deposit(user, "Bank of Test", now, 10.0);

    const std::string& query = "Bank of Test";
    auto transactions = api->searchTransactionsByBank(user,query);

    std::cout << "Transactions by Bank:\n";
    for (const auto& transaction : transactions) {
        std::string decryptedBank = api->decryptString(user, transaction.encryptedBankName);
        std::time_t decryptedTime = std::stoll(api->decryptString(user, transaction.encryptedDate));
        std::chrono::system_clock::time_point transactionDate = std::chrono::system_clock::from_time_t(decryptedTime);
        double decryptedAmount = api->decryptDouble(user, transaction.encryptedAmount);

        std::time_t t = std::chrono::system_clock::to_time_t(transactionDate);
        std::cout << decryptedBank << " " << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S") << " - " << transaction.type << ": " << decryptedAmount << "\n";
    }

    std::cout << "Total Balance: " << api->decryptDouble(user,api->getTotalBalance(user)) << "\n";
}

void testLatency(){
    auto api = OpenBankingAPI::Create();
        
    helib::SecKey secKey = api->generateSecurityKey();
    helib::PubKey pk= api->generatePublicKey(secKey);
    User user(pk, secKey);
    Bank bank1 = {"Bank of Example"};
    Bank bank2 = {"Bank of Test"};
    api->registerBank(user, bank1);
    api->registerBank(user, bank2);

    auto now = std::chrono::system_clock::now();

    double avg_encryption = 0;
    for(int i = 0;i<5;i++){
        //Encryption of simple transactions
        // Measure the start time
        auto start = std::chrono::high_resolution_clock::now();
        api->deposit(user, "Bank of Example", now, 100.0);  
        // Measure the end time
        auto end = std::chrono::high_resolution_clock::now();
        // Calculate the duration
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        avg_encryption += duration.count();
    }

    cout << "enc\n";


    //Encryption of transactions mult
    double avg_encryption_mult = 0;
    for(int i = 0;i<5;i++){
        //Encryption of multiplication transactions
        // Measure the start time
        auto start = std::chrono::high_resolution_clock::now();
        api->savings(user, "Bank of Test", now, 100.0, 0.35);  
        // Measure the end time
        auto end = std::chrono::high_resolution_clock::now();
        // Calculate the duration
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        avg_encryption_mult += duration.count();
    }
    cout << "mult\n";
    
    //Search by bank name
    double avg_search_bank = 0;
    for(int i = 0;i<5;i++){
        // Measure the start time
        auto start = std::chrono::high_resolution_clock::now();
        const std::string& query = "Bank of Test";
        auto transactions = api->searchTransactionsByBank(user,query);
        // Measure the end time
        auto end = std::chrono::high_resolution_clock::now();
        // Calculate the duration
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        avg_search_bank += duration.count();
    }

    //Search by amount
    double avg_search_amount = 0;
    for(int i = 0;i<5;i++){
        // Measure the start time
        auto start = std::chrono::high_resolution_clock::now();
        const std::string& query = "Bank of Test";
        auto transactions = api->searchTransactionsByValue(user,100.0);
        // Measure the end time
        auto end = std::chrono::high_resolution_clock::now();
        // Calculate the duration
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        avg_search_amount += duration.count();
    }

    //Decryption of transactions
    const std::string& query = "Bank of Test";
    auto transactions = api->searchTransactionsByBank(user,query);
    double avg_dec = 0;
    auto start = std::chrono::high_resolution_clock::now();
    for(auto t : transactions){        
        std::string decryptedBank = api->decryptString(user, t.encryptedBankName);
        std::time_t decryptedTime = std::stoll(api->decryptString(user, t.encryptedDate));
        std::chrono::system_clock::time_point transactionDate = std::chrono::system_clock::from_time_t(decryptedTime);
        double decryptedAmount = api->decryptDouble(user, t.encryptedAmount);
    }  
    // Measure the end time
    auto end = std::chrono::high_resolution_clock::now();
    // Calculate the duration
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    avg_dec += duration.count();

    double avg_add = 0;
    start = std::chrono::high_resolution_clock::now();
    api->getTotalBalance(user);
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    avg_add += duration.count();



    // Output the latency
    std::cout << "Latency simple encryption: " << avg_encryption/5 << " microseconds" << std::endl;
    std::cout << "Latency multiplication encryption: " << avg_encryption_mult/5 << " microseconds" << std::endl;
    std::cout << "Latency search bank : " << avg_search_bank/5 << " microseconds" << std::endl;
    std::cout << "Latency search amount : " << avg_search_amount/5 << " microseconds" << std::endl;
    std::cout << "Latency decryption : " << avg_dec/5 << " microseconds" << std::endl;
    std::cout << "Latency add : " << avg_add/10 << " microseconds" << std::endl;

}

void testSize(){
    auto api = OpenBankingAPI::Create();
        
    helib::SecKey secKey = api->generateSecurityKey();
    helib::PubKey pk= api->generatePublicKey(secKey);
    User user(pk, secKey);

    cout << sizeof(pk) << " : pk size\n";
    cout << sizeof(secKey) << " : sk size\n";

    Bank bank1 = {"Bank of Example"};
    Bank bank2 = {"Bank of Test"};
    api->registerBank(user, bank1);
    api->registerBank(user, bank2);

    auto now = std::chrono::system_clock::now();

    api->deposit(user, "Bank of Example", now, 100.0);  

    cout << sizeof(user.transactions[0]) << " : size of transaction\n";
}

void testNoiseGrowth(){
    auto api = OpenBankingAPI::Create();
        
    helib::SecKey secKey = api->generateSecurityKey();
    helib::PubKey pk= api->generatePublicKey(secKey);
    User user(pk, secKey);

    auto a = api->encryptDouble(user, 34.9);
    auto b = api->encryptDouble(user, 3.4);

    auto c = a;
    c *= b;
    auto d = a;
    d += b;

    cout << a.errorBound() << " : a\n";
    cout << b.errorBound()<< " : b\n";
    cout << c.errorBound()<< " : c\n";
    cout << d.errorBound()<< " : d\n"; 

    helib::Ctxt total = a;
    int totalMult = 1;
    while(total.capacity() > 0){
        total *= total;
        totalMult += 1;
    }
    cout << totalMult << "mults\n";

}

int main() {
    
    testFunctionalities();
    testLatency();
    testSize();
    testNoiseGrowth();

    return 0;
}
