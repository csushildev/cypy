import torch
import torch.nn as nn
import torch.optim as optim
import torchvision
import torchvision.transforms as transforms

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

aug = transforms.Compose([
    transforms.RandomHorizontalFlip(),
    transforms.RandomCrop(32, padding=4),
    transforms.ToTensor(),
    transforms.Normalize((0.4914, 0.4822, 0.4465), (0.247, 0.243, 0.261))
])

plain = transforms.Compose([
    transforms.ToTensor(),
    transforms.Normalize((0.4914, 0.4822, 0.4465), (0.247, 0.243, 0.261))
])

train_set = torchvision.datasets.CIFAR10(root="./data", train=True, download=True, transform=aug)
test_set  = torchvision.datasets.CIFAR10(root="./data", train=False, download=True, transform=plain)

train_loader = torch.utils.data.DataLoader(train_set, batch_size=128, shuffle=True, num_workers=2)
test_loader  = torch.utils.data.DataLoader(test_set,  batch_size=256, shuffle=False, num_workers=2)

classes = ("plane","car","bird","cat","deer","dog","frog","horse","ship","truck")


class ConvNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.features = nn.Sequential(
            nn.Conv2d(3, 32, 3, padding=1), nn.BatchNorm2d(32), nn.ReLU(),
            nn.Conv2d(32, 64, 3, padding=1), nn.BatchNorm2d(64), nn.ReLU(),
            nn.MaxPool2d(2),
            nn.Dropout2d(0.25),

            nn.Conv2d(64, 128, 3, padding=1), nn.BatchNorm2d(128), nn.ReLU(),
            nn.Conv2d(128, 128, 3, padding=1), nn.BatchNorm2d(128), nn.ReLU(),
            nn.MaxPool2d(2),
            nn.Dropout2d(0.25),
        )
        self.head = nn.Sequential(
            nn.Flatten(),
            nn.Linear(128 * 8 * 8, 512), nn.ReLU(), nn.Dropout(0.5),
            nn.Linear(512, 10)
        )

    def forward(self, x):
        return self.head(self.features(x))


conv_net = ConvNet().to(device)
loss_fn  = nn.CrossEntropyLoss()
opt      = optim.SGD(conv_net.parameters(), lr=0.1, momentum=0.9, weight_decay=5e-4)
# cosine decay feels cleaner than step-wise here
scheduler = optim.lr_scheduler.CosineAnnealingLR(opt, T_max=50)


def run_epoch(loader, training=True):
    conv_net.train() if training else conv_net.eval()
    total_loss, correct, n = 0.0, 0, 0
    ctx = torch.enable_grad() if training else torch.no_grad()
    with ctx:
        for imgs, labels in loader:
            imgs, labels = imgs.to(device), labels.to(device)
            preds = conv_net(imgs)
            loss  = loss_fn(preds, labels)
            if training:
                opt.zero_grad()
                loss.backward()
                opt.step()
            total_loss += loss.item() * labels.size(0)
            correct    += (preds.argmax(1) == labels).sum().item()
            n          += labels.size(0)
    return total_loss / n, correct / n


# TODO: bump EPOCHS to 100+ if accuracy plateaus around 85%
EPOCHS = 1 # keeping low for testing purpose.
for ep in range(1, EPOCHS + 1):
    tr_loss, tr_acc = run_epoch(train_loader, training=True)
    va_loss, va_acc = run_epoch(test_loader,  training=False)
    scheduler.step()
    if ep % 5 == 0 or ep == 1:
        print(f"ep {ep:>3} | train {tr_acc:.3f} loss {tr_loss:.4f} | val {va_acc:.3f} loss {va_loss:.4f}")

torch.save(conv_net.state_dict(), "cifar10_conv.pt")
print("saved → cifar10_conv.pt")