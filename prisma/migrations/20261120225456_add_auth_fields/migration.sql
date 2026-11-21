-- AlterTable
ALTER TABLE "User" ADD COLUMN     "refreshTokenHash" TEXT,
ADD COLUMN     "roles" TEXT[] DEFAULT ARRAY['customer']::TEXT[];
