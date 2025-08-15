declare module 'chainwise' {
    export interface NetworkConfig {
        name: string;
        symbol: string;
        tier: number;
        status: 'live' | 'beta' | 'planned';
        coinType: number;
        curve: 'secp256k1' | 'ed25519' | 'sr25519';
        features: string[];
        explorer: string;
        addressFormats: string[];
        derivationPath: string;
        implementation: 'native' | 'bundler';
    }

    export interface WalletOptions {
        maxWorkers?: number;
        workerTimeout?: number;
        enableLogging?: boolean;
        autoSave?: boolean;
        defaultNetworks?: string[] | null;
    }

    export interface SignatureResult {
        message: string;
        signature: any;
        network: string;
        address: string;
        curve: string;
        recoveryParam?: number;
    }

    export class CryptoWallet {
        constructor(options?: WalletOptions);
        
        initialize(password: string): Promise<void>;
        unlock(password: string): Promise<boolean>;
        lock(): void;
        
        importSeed(seedHex: string, password: string): Promise<void>;
        exportSeed(): string;
        
        getAddress(network: string, addressType?: string): string;
        getAllAddresses(): Record<string, any>;
        
        signMessage(message: string, network: string): Promise<SignatureResult>;
        verifyMessage(message: string, signature: any, network?: string): Promise<any>;
        
        generateMultipleAddresses(network: string, count: number, change?: number): Promise<any[]>;
        
        getSupportedNetworks(): NetworkConfig[];
        getNetworkConfig(network: string): NetworkConfig | null;
        
        getStatus(): any;
        getMetrics(): any;
        
        clearWallet(): Promise<void>;
        destroy(): void;
    }

    export const NETWORK_CONFIGS: Record<string, NetworkConfig>;
    export default CryptoWallet;
}