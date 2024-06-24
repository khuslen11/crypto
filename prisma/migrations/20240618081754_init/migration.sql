-- CreateTable
CREATE TABLE "api_user" (
    "user_id" SERIAL NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,

    CONSTRAINT "api_user_pkey" PRIMARY KEY ("user_id")
);

-- CreateIndex
CREATE UNIQUE INDEX "api_user_email_key" ON "api_user"("email");
