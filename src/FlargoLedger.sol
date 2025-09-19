// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract FlargoLedger {
    enum Role { CUSTOMER, FARMER, DISTRIBUTOR, RETAILER, ADMIN }
    enum TransactionType { USER_REGISTRATION, PRODUCT_REGISTRATION, ORDER_CREATION, STATUS_UPDATE, INVENTORY_UPDATE }
    enum Status { PENDING, CONFIRMED, CANCELLED }

    struct LedgerEntry {
        uint256 id;
        address signer;
        bytes32 dataHash;
        TransactionType txType;
        Status status;
        uint256 timestamp;
        string metadata;
        bool exists;
    }

    struct User {
        string id;
        address wallet;
        string name;
        Role role;
        string email;
        string contactNumber;
        uint256 timestamp;
        bool active;
    }

    struct Product {
        string id;
        string name;
        string category;
        string farmerId;
        uint256 pricePerUnit;
        uint256 timestamp;
        bool active;
    }

    struct Order {
        string id;
        string buyerId;
        string sellerId;
        string productId;
        uint256 quantity;
        uint256 totalAmount;
        Status status;
        uint256 timestamp;
        bool active;
    }

    mapping(uint256 => LedgerEntry) public ledger;
    mapping(address => string) public walletToUserId;
    mapping(string => User) public users;
    mapping(string => Product) public products;
    mapping(string => Order) public orders;
    
    uint256 public ledgerCounter;
    address public admin;

    event LedgerEntryCreated(uint256 indexed entryId, address indexed signer, bytes32 dataHash, TransactionType txType);
    event TransactionConfirmed(uint256 indexed entryId, address indexed confirmer);
    event UserRegistered(string indexed userId, address indexed wallet);
    event ProductRegistered(string indexed productId, string farmerId);
    event OrderCreated(string indexed orderId, string buyerId, string sellerId);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin access");
        _;
    }

    modifier onlyRegisteredUser() {
        require(bytes(walletToUserId[msg.sender]).length > 0, "User not registered");
        _;
    }

    modifier validSignature(bytes32 dataHash, bytes memory signature) {
        require(_verifySignature(dataHash, signature, msg.sender), "Invalid signature");
        _;
    }

    constructor() {
        admin = msg.sender;
        ledgerCounter = 1;
    }

    function registerUser(
        string memory _userId,
        string memory _name,
        Role _role,
        string memory _email,
        string memory _contactNumber,
        bytes memory _signature
    ) external {
        require(bytes(walletToUserId[msg.sender]).length == 0, "Wallet already registered");
        require(!users[_userId].active, "User ID already exists");

        bytes32 dataHash = keccak256(abi.encodePacked(_userId, _name, uint256(_role), _email, _contactNumber, msg.sender));
        require(_verifySignature(dataHash, _signature, msg.sender), "Invalid signature");

        users[_userId] = User({
            id: _userId,
            wallet: msg.sender,
            name: _name,
            role: _role,
            email: _email,
            contactNumber: _contactNumber,
            timestamp: block.timestamp,
            active: true
        });

        walletToUserId[msg.sender] = _userId;

        _createLedgerEntry(dataHash, TransactionType.USER_REGISTRATION, string(abi.encodePacked("User:", _userId)));

        emit UserRegistered(_userId, msg.sender);
    }

    function registerProduct(
        string memory _productId,
        string memory _name,
        string memory _category,
        uint256 _pricePerUnit,
        bytes memory _signature
    ) external onlyRegisteredUser {
        require(!products[_productId].active, "Product already exists");
        require(users[walletToUserId[msg.sender]].role == Role.FARMER, "Only farmers can register products");

        string memory farmerId = walletToUserId[msg.sender];
        bytes32 dataHash = keccak256(abi.encodePacked(_productId, _name, _category, farmerId, _pricePerUnit));
        require(_verifySignature(dataHash, _signature, msg.sender), "Invalid signature");

        products[_productId] = Product({
            id: _productId,
            name: _name,
            category: _category,
            farmerId: farmerId,
            pricePerUnit: _pricePerUnit,
            timestamp: block.timestamp,
            active: true
        });

        _createLedgerEntry(dataHash, TransactionType.PRODUCT_REGISTRATION, string(abi.encodePacked("Product:", _productId)));

        emit ProductRegistered(_productId, farmerId);
    }

    function createOrder(
        string memory _orderId,
        string memory _sellerId,
        string memory _productId,
        uint256 _quantity,
        bytes memory _signature
    ) external onlyRegisteredUser {
        require(!orders[_orderId].active, "Order already exists");
        require(users[_sellerId].active, "Seller not found");
        require(products[_productId].active, "Product not found");

        string memory buyerId = walletToUserId[msg.sender];
        uint256 totalAmount = _quantity * products[_productId].pricePerUnit;
        
        bytes32 dataHash = keccak256(abi.encodePacked(_orderId, buyerId, _sellerId, _productId, _quantity, totalAmount));
        require(_verifySignature(dataHash, _signature, msg.sender), "Invalid signature");

        orders[_orderId] = Order({
            id: _orderId,
            buyerId: buyerId,
            sellerId: _sellerId,
            productId: _productId,
            quantity: _quantity,
            totalAmount: totalAmount,
            status: Status.PENDING,
            timestamp: block.timestamp,
            active: true
        });

        _createLedgerEntry(dataHash, TransactionType.ORDER_CREATION, string(abi.encodePacked("Order:", _orderId)));

        emit OrderCreated(_orderId, buyerId, _sellerId);
    }

    function confirmTransaction(uint256 _entryId, bytes memory _signature) external {
        require(ledger[_entryId].exists, "Entry does not exist");
        require(ledger[_entryId].status == Status.PENDING, "Transaction already processed");

        bytes32 confirmHash = keccak256(abi.encodePacked(_entryId, "CONFIRM", block.timestamp));
        require(_verifySignature(confirmHash, _signature, msg.sender), "Invalid confirmation signature");

        ledger[_entryId].status = Status.CONFIRMED;
        
        emit TransactionConfirmed(_entryId, msg.sender);
    }

    function updateOrderStatus(
        string memory _orderId,
        Status _status,
        bytes memory _signature
    ) external onlyRegisteredUser {
        require(orders[_orderId].active, "Order not found");
        
        string memory userId = walletToUserId[msg.sender];
        require(
            keccak256(bytes(orders[_orderId].sellerId)) == keccak256(bytes(userId)) ||
            keccak256(bytes(orders[_orderId].buyerId)) == keccak256(bytes(userId)),
            "Not authorized to update this order"
        );

        bytes32 dataHash = keccak256(abi.encodePacked(_orderId, uint256(_status), block.timestamp));
        require(_verifySignature(dataHash, _signature, msg.sender), "Invalid signature");

        orders[_orderId].status = _status;

        _createLedgerEntry(dataHash, TransactionType.STATUS_UPDATE, string(abi.encodePacked("OrderStatus:", _orderId)));
    }

    function _createLedgerEntry(
        bytes32 _dataHash,
        TransactionType _txType,
        string memory _metadata
    ) internal {
        ledger[ledgerCounter] = LedgerEntry({
            id: ledgerCounter,
            signer: msg.sender,
            dataHash: _dataHash,
            txType: _txType,
            status: Status.CONFIRMED,
            timestamp: block.timestamp,
            metadata: _metadata,
            exists: true
        });

        emit LedgerEntryCreated(ledgerCounter, msg.sender, _dataHash, _txType);
        ledgerCounter++;
    }

    function _verifySignature(
        bytes32 _hash,
        bytes memory _signature,
        address _signer
    ) internal pure returns (bool) {
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _hash));
        return _recoverSigner(ethSignedHash, _signature) == _signer;
    }

    function _recoverSigner(bytes32 _hash, bytes memory _signature) internal pure returns (address) {
        require(_signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
            v := byte(0, mload(add(_signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature v value");

        return ecrecover(_hash, v, r, s);
    }

    function getLedgerEntry(uint256 _entryId) external view returns (LedgerEntry memory) {
        require(ledger[_entryId].exists, "Entry does not exist");
        return ledger[_entryId];
    }

    function getUserByWallet(address _wallet) external view returns (User memory) {
        string memory userId = walletToUserId[_wallet];
        require(bytes(userId).length > 0, "User not found");
        return users[userId];
    }

    function getProduct(string memory _productId) external view returns (Product memory) {
        require(products[_productId].active, "Product not found");
        return products[_productId];
    }

    function getOrder(string memory _orderId) external view returns (Order memory) {
        require(orders[_orderId].active, "Order not found");
        return orders[_orderId];
    }

    function verifyDataIntegrity(uint256 _entryId, bytes32 _expectedHash) external view returns (bool) {
        require(ledger[_entryId].exists, "Entry does not exist");
        return ledger[_entryId].dataHash == _expectedHash;
    }

    function getLedgerHistory(uint256 _fromId, uint256 _toId) external view returns (LedgerEntry[] memory) {
        require(_fromId <= _toId && _toId < ledgerCounter, "Invalid range");
        
        uint256 length = _toId - _fromId + 1;
        LedgerEntry[] memory entries = new LedgerEntry[](length);
        
        for (uint256 i = 0; i < length; i++) {
            entries[i] = ledger[_fromId + i];
        }
        
        return entries;
    }

    function getTotalEntries() external view returns (uint256) {
        return ledgerCounter - 1;
    }

    function isUserRegistered(address _wallet) external view returns (bool) {
        return bytes(walletToUserId[_wallet]).length > 0;
    }
}