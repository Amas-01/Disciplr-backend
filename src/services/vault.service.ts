import { Vault, CreateVaultDTO, VaultStatus } from '../types/vault.js';

// Assuming you have a configured pg pool exported from your db setup
import pool from '../db/index.js'; 

export class VaultService {
  /**
   * Creates a new vault record in the database.
   */
  static async createVault(data: CreateVaultDTO): Promise<Vault> {
    const query = `
      INSERT INTO vaults (
        contract_id, creator_address, amount, milestone_hash, 
        verifier_address, success_destination, failure_destination, deadline
      ) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
      RETURNING *;
    `;
    
    const values = [
      data.contractId, data.creatorAddress, data.amount, data.milestoneHash,
      data.verifierAddress, data.successDestination, data.failureDestination, data.deadline
    ];

    try {
      const result = await pool.query(query, values);
      return result.rows[0];
    } catch (error) {
      console.error('Error creating vault:', error);
      throw new Error('Database error during vault creation');
    }
}

// Use Prisma only when DATABASE_URL is available
let prisma: any
try {
    if (process.env.DATABASE_URL) {
        const { prisma: realPrisma } = await import('../lib/prisma.js')
        prisma = realPrisma
    } else {
        prisma = mockPrisma
    }
} catch {
    prisma = mockPrisma
}
